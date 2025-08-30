import time
import socket
import subprocess
import logging
import json
import os
import signal
from contextlib import closing
from statistics import mean, median
from typing import Dict, Optional, Tuple, List
from collections import deque
from threading import Event

try:
    from prometheus_client import start_http_server, Gauge, Histogram
    PROM_ENABLED = True
except Exception:
    PROM_ENABLED = False

LOG_LEVEL = os.environ.get("MINIVPN_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

FILL_ZEROS = os.environ.get("MINIVPN_FILL_ZEROS", "false").lower() == "true"

def run_cmd(argv: List[str], timeout: float = 5.0) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return cp.returncode, cp.stdout or "", cp.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, "", f"timeout: {e}"
    except OSError as e:
        return 1, "", f"oserror: {e}"
    except Exception as e:
        return 1, "", f"error: {e}"

def safe_section(name: str, fn, default=None):
    try:
        return fn()
    except Exception as e:
        logger.error(f"{name} error: {e}")
        return default

class MiniVPNMetrics:
    def __init__(
        self,
        rtt_host: str = "1.1.1.1",
        rtt_port: int = 443,
        rtt_attempts: int = 5,
        rtt_timeout: float = 0.6,
        iface_hint: Optional[str] = None,
        prom_port: Optional[int] = None,
        output_format: str = "log",
        speed_interval: float = 1.5,
        speed_samples: int = 3,
        window_size: int = 5
    ):
        self.rtt_host = rtt_host
        self.rtt_port = rtt_port
        self.rtt_attempts = max(1, rtt_attempts)
        self.rtt_timeout = rtt_timeout
        self.iface_hint = iface_hint
        self.prom_port = prom_port
        self.output_format = output_format
        self.speed_interval = max(0.2, speed_interval)
        self.speed_samples = max(1, speed_samples)
        self.process_start = time.time()
        # Скользящие окна
        self.rtt_window = deque(maxlen=max(1, window_size))
        self.rx_window = deque(maxlen=max(1, window_size))
        self.tx_window = deque(maxlen=max(1, window_size))

        if PROM_ENABLED and self.prom_port:
            # RTT в секундах
            self.h_rtt = Histogram(
                "minivpn_rtt_connect_seconds",
                "TCP connect RTT to target",
                buckets=(0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0)
            )
            self.g_rx_mbps = Gauge("minivpn_rx_mbps", "RX throughput on VPN interface")
            self.g_tx_mbps = Gauge("minivpn_tx_mbps", "TX throughput on VPN interface")
            self.g_vpn_up = Gauge("minivpn_vpn_up", "VPN interface up (1) or down (0)")
            self.g_rx_errors = Gauge("minivpn_rx_errors", "RX errors on VPN interface")
            self.g_tx_errors = Gauge("minivpn_tx_errors", "TX errors on VPN interface")
            self.g_rx_dropped = Gauge("minivpn_rx_dropped", "RX dropped on VPN interface")
            self.g_tx_dropped = Gauge("minivpn_tx_dropped", "TX dropped on VPN interface")
            self.g_uptime = Gauge("minivpn_process_uptime_seconds", "Process uptime seconds")
            try:
                start_http_server(self.prom_port)
                logger.info(f"Prometheus exporter listening on :{self.prom_port}")
            except OSError as e:
                logger.warning(f"Failed to start Prometheus exporter: {e}")

    def tcp_rtt_samples(
        self,
        attempts: Optional[int] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: Optional[float] = None
    ) -> List[float]:
        n = attempts or self.rtt_attempts
        h = host or self.rtt_host
        p = port or self.rtt_port
        to = timeout or self.rtt_timeout
        samples: List[float] = []
        last_err = None
        for _ in range(n):
            t0 = time.time()
            try:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                    s.settimeout(to)
                    s.connect((h, p))
                    samples.append(time.time() - t0)
            except socket.timeout:
                last_err = f"timeout>{to}s"
            except ConnectionRefusedError:
                last_err = "conn_refused"
            except OSError as e:
                last_err = f"oserror:{getattr(e,'errno',-1)}"
            except Exception as e:
                last_err = f"error:{type(e).__name__}"
        if not samples and last_err:
            logger.warning(f"RTT failed to {h}:{p} attempts={n} reason={last_err}")
        return samples

    def rtt_summary_ms(self) -> Dict[str, float]:
        s = self.tcp_rtt_samples()
        if not s:
            return {"avg": -1.0, "p50": -1.0, "p90": -1.0, "p99": -1.0, "ok": 0.0, "count": 0.0}
        s_sorted = sorted(s)
        def pct(p):
            idx = max(0, min(len(s_sorted) - 1, int(round((p/100.0) * (len(s_sorted)-1)))))
            return s_sorted[idx] * 1000.0
        avg_ms = mean(s_sorted) * 1000.0
        # сглаживание окна
        self.rtt_window.append(avg_ms)
        avg_ms_smoothed = median(self.rtt_window)
        return {
            "avg": avg_ms_smoothed,
            "p50": pct(50),
            "p90": pct(90),
            "p99": pct(99),
            "ok": 1.0,
            "count": float(len(s_sorted))
        }

    def get_vpn_interface(self, retries: int = 3, base_delay: float = 0.5) -> Optional[str]:
        if self.iface_hint:
            return self.iface_hint
        for i in range(max(1, retries)):
            rc, out, err = run_cmd(["ip", "-j", "link"])
            if rc == 0:
                try:
                    interfaces = json.loads(out)
                    for iface in interfaces:
                        name = iface.get("ifname") or ""
                        state = (iface.get("operstate") or "").upper()
                        if name.startswith(("wg", "tun", "tap")) and state == "UP":
                            if i > 0:
                                logger.info(f"VPN interface detected after {i+1} tries: {name}")
                            return name
                except json.JSONDecodeError:
                    logger.debug("ip -j link JSON decode error.")
            else:
                logger.debug(f"ip -j link failed (rc={rc}): {err}")
            time.sleep(base_delay * (2 ** i))
        logger.warning("VPN interface not found after retries.")
        return None

    def iface_stats(self, ifname: str) -> Optional[Dict[str, int]]:
        rc, out, err = run_cmd(["ip", "-s", "link", "show", ifname])
        if rc != 0:
            logger.warning(f"ip -s link show {ifname} failed (rc={rc}): {err}")
            return None
        rx_bytes = tx_bytes = rx_err = tx_err = rx_drop = tx_drop = 0
        lines = out.splitlines()
        idx = 0
        while idx < len(lines):
            line = lines[idx].strip().lower()
            if line.startswith("rx:") and idx + 1 < len(lines):
                vals = lines[idx + 1].strip().split()
                try:
                    # обычно: bytes packets errors dropped fifo frame compressed multicast
                    rx_bytes = int(vals); rx_err = int(vals[2]); rx_drop = int(vals[3])
                except (IndexError, ValueError) as e:
                    logger.debug(f"Parse RX error: {e}")
                idx += 2
                continue
            if line.startswith("tx:") and idx + 1 < len(lines):
                vals = lines[idx + 1].strip().split()
                try:
                    tx_bytes = int(vals); tx_err = int(vals[2]); tx_drop = int(vals[3])
                except (IndexError, ValueError) as e:
                    logger.debug(f"Parse TX error: {e}")
                idx += 2
                continue
            idx += 1
        return {
            "rx_bytes": rx_bytes, "tx_bytes": tx_bytes,
            "rx_errors": rx_err, "tx_errors": tx_err,
            "rx_dropped": rx_drop, "tx_dropped": tx_drop
        }

    def estimate_throughput_mbps(
        self, ifname: str, samples: Optional[int] = None, interval: Optional[float] = None
    ) -> Dict[str, float]:
        N = max(1, samples or self.speed_samples)
        iv = max(0.2, interval or self.speed_interval)
        rx_list: List[float] = []
        tx_list: List[float] = []
        prev = self.iface_stats(ifname)
        if not prev:
            return {"rx_mbps": -1.0, "tx_mbps": -1.0}
        for _ in range(N):
            time.sleep(iv)
            curr = self.iface_stats(ifname)
            if not curr:
                continue
            rx_bps = max(0, curr["rx_bytes"] - prev["rx_bytes"]) / iv
            tx_bps = max(0, curr["tx_bytes"] - prev["tx_bytes"]) / iv
            rx_list.append((rx_bps * 8.0) / 1_000_000.0)
            tx_list.append((tx_bps * 8.0) / 1_000_000.0)
            prev = curr
        if not rx_list and not tx_list:
            return {"rx_mbps": -1.0, "tx_mbps": -1.0}
        rx_med = median(rx_list) if rx_list else 0.0
        tx_med = median(tx_list) if tx_list else 0.0
        self.rx_window.append(rx_med)
        self.tx_window.append(tx_med)
        return {
            "rx_mbps": median(self.rx_window) if self.rx_window else rx_med,
            "tx_mbps": median(self.tx_window) if self.tx_window else tx_med
        }

    def get_vpn_status(self) -> Dict[str, str]:
        ifname = self.get_vpn_interface()
        return {"vpn_interface": ifname or "N/A", "status": "active" if ifname else "inactive"}

    def collect_metrics(self) -> Dict[str, object]:
        metrics: Dict[str, object] = {}
        # RTT
        rtt = safe_section("RTT", self.rtt_summary_ms, default={"avg": -1.0, "p50": -1.0, "p90": -1.0, "p99": -1.0, "ok": 0.0, "count": 0.0})
        metrics.update({
            "rtt_avg_ms": None if rtt["avg"] < 0 else round(rtt["avg"], 2),
            "rtt_p50_ms": None if rtt["p50"] < 0 else round(rtt["p50"], 2),
            "rtt_p90_ms": None if rtt["p90"] < 0 else round(rtt["p90"], 2),
            "rtt_p99_ms": None if rtt["p99"] < 0 else round(rtt["p99"], 2),
            "rtt_ok": int(rtt["ok"]),
            "rtt_samples_count": int(rtt["count"])
        })
        # VPN status
        status = safe_section("VPN status", self.get_vpn_status, default={"vpn_interface": "N/A", "status": "inactive"})
        metrics["vpn_interface"] = status["vpn_interface"]
        metrics["vpn_status"] = status["status"]
        # Throughput + errors
        if status["status"] == "active":
            ifname = status["vpn_interface"]
            thr = safe_section("Throughput", lambda: self.estimate_throughput_mbps(ifname), default={"rx_mbps": -1.0, "tx_mbps": -1.0})
            if thr and thr.get("rx_mbps", -1.0) >= 0:
                metrics["rx_mbps"] = round(thr["rx_mbps"], 3)
                metrics["tx_mbps"] = round(thr["tx_mbps"], 3)
            elif FILL_ZEROS:
                metrics["rx_mbps"] = 0.0
                metrics["tx_mbps"] = 0.0
            st = safe_section("Iface stats", lambda: self.iface_stats(ifname), default=None)
            if st:
                metrics["rx_errors"] = st["rx_errors"]
                metrics["tx_errors"] = st["tx_errors"]
                metrics["rx_dropped"] = st["rx_dropped"]
                metrics["tx_dropped"] = st["tx_dropped"]
            elif FILL_ZEROS:
                metrics.update({"rx_errors": 0, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0})
        else:
            if FILL_ZEROS:
                metrics.update({"rx_mbps": 0.0, "tx_mbps": 0.0, "rx_errors": 0, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0})
        # Uptime
        uptime = time.time() - self.process_start
        metrics["process_uptime_sec"] = int(uptime)
        # Prometheus
        if PROM_ENABLED and self.prom_port:
            try:
                if metrics.get("rtt_ok") == 1 and metrics.get("rtt_avg_ms") is not None:
                    self.h_rtt.observe(max(metrics["rtt_avg_ms"] / 1000.0, 0.0))
                self.g_vpn_up.set(1 if status["status"] == "active" else 0)
                if status["status"] == "active" and metrics.get("rx_mbps") is not None:
                    self.g_rx_mbps.set(float(metrics["rx_mbps"]))
                    self.g_tx_mbps.set(float(metrics["tx_mbps"]))
                if "rx_errors" in metrics:
                    self.g_rx_errors.set(float(metrics["rx_errors"]))
                    self.g_tx_errors.set(float(metrics["tx_errors"]))
                    self.g_rx_dropped.set(float(metrics["rx_dropped"]))
                    self.g_tx_dropped.set(float(metrics["tx_dropped"]))
                self.g_uptime.set(uptime)
            except Exception as e:
                logger.debug(f"Prometheus export error: {e}")
        return metrics

    def display_metrics(self):
        m = self.collect_metrics()
        if self.output_format == "json":
            print(json.dumps(m, ensure_ascii=False))
        else:
            for k, v in m.items():
                logger.info(f"{k}: {v}")

def main_loop():
    rtt_host = os.environ.get("MINIVPN_RTT_HOST", "1.1.1.1")
    rtt_port = int(os.environ.get("MINIVPN_RTT_PORT", "443"))
    iface_hint = os.environ.get("MINIVPN_IFACE")
    prom_port_env = os.environ.get("MINIVPN_PROM_PORT", "")
    prom_port = int(prom_port_env) if prom_port_env.isdigit() else None
    metrics_interval = float(os.environ.get("MINIVPN_METRICS_INTERVAL", "15"))
    speed_interval = float(os.environ.get("MINIVPN_SPEED_INTERVAL", "1.5"))
    speed_samples = int(os.environ.get("MINIVPN_SPEED_SAMPLES", "3"))
    output_format = os.environ.get("MINIVPN_OUTPUT", "log").lower()

    collector = MiniVPNMetrics(
        rtt_host=rtt_host,
        rtt_port=rtt_port,
        rtt_attempts=5,
        rtt_timeout=0.6,
        iface_hint=iface_hint,
        prom_port=prom_port,
        output_format=output_format,
        speed_interval=speed_interval,
        speed_samples=speed_samples,
        window_size=int(os.environ.get("MINIVPN_WINDOW_SIZE", "5"))
    )

    stop = Event()
    def handle_sig(sig, frame):
        stop.set()
        logger.info("Stopping metrics loop...")

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    step = 0.5
    next_tick = time.time()
    while not stop.is_set():
        if time.time() >= next_tick:
            safe_section("Tick", collector.display_metrics)
            next_tick = time.time() + max(1.0, metrics_interval)
        stop.wait(step)

if __name__ == "__main__":
    main_loop()
