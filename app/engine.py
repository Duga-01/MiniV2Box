import json
import threading
import logging
from typing import Optional
from dataclasses import asdict

from config import Profile, RealitySettings, ShadowsocksSettings
from config import load_config, prepare_session, get_active_profile, ensure_logs_dir
import xray  # из пакета xray-core: startFromJSON/queryStats

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

class XrayInstance:
    def __init__(self, json_cfg: str):
        self.json_cfg = json_cfg
        self.started = False

class Engine:
    def __init__(self):
        self.current: Optional[XrayInstance] = None
        self.lock = threading.Lock()

    def _validate_reality(self, r: RealitySettings):
        sid = (r.short_id or "").lower()
        if sid and (len(sid) > 16 or any(c not in "0123456789abcdef" for c in sid)):
            raise ValueError(f"Invalid short_id: {r.short_id}. Must be hex up to 16 chars.")

    def _render_vless_reality(self, p: Profile) -> dict:
        r = p.reality
        if not r:
            raise ValueError(f"Missing Reality settings for profile {p.name}.")
        self._validate_reality(r)
        address = p.cname_endpoint or r.server
        masked = {**asdict(r), "public_key": "****"}
        try:
            logger.debug(
                f"Generated VLESS Reality config for profile {p.name}: {json.dumps(masked, ensure_ascii=False, indent=2)}"
            )
        except Exception:
            pass
        vless_outbound = {
            "tag": "vless-out",
            "protocol": "vless",
            "settings": {
                "packetEncoding": "xudp",
                "vnext": [{
                    "address": address,
                    "port": r.port,
                    "users": [{
                        "id": r.user_id or "00000000-0000-0000-0000-000000000001",
                        "email": "",
                        "encryption": "none",
                        "flow": r.flow
                    }]
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": r.sni,
                    "fingerprint": "chrome",
                    "show": False,
                    "publicKey": r.public_key,
                    "shortId": r.short_id,
                    "spiderX": "/"
                },
                "tlsSettings": {
                    "alpn": p.tls_alpn or ["h2", "http/1.1"],
                    "serverName": p.tls_server_name or r.sni
                }
            },
            "mux": {"enabled": False}
        }
        return {
            "log": {"loglevel": "info"},
            "api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["StatsService"]},
            "policy": {
                "system": {
                    "statsInboundUplink": True,
                    "statsInboundDownlink": True,
                    "statsOutboundUplink": True,
                    "statsOutboundDownlink": True
                },
                "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}
            },
            "stats": {},
            "inbounds": [{
                "tag": "socks-in",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
                "sniffing": {"enabled": False, "destOverride": ["http", "tls"]}
            }],
            "outbounds": [vless_outbound]
        }

    def _render_shadowsocks(self, p: Profile) -> dict:
        s = p.shadowsocks
        if not s:
            raise ValueError(f"Missing Shadowsocks settings for profile {p.name}.")
        return {
            "log": {"loglevel": "info"},
            "inbounds": [{
                "tag": "socks-in",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
                "sniffing": {"enabled": False, "destOverride": ["http", "tls"]}
            }],
            "outbounds": [{
                "tag": "ss-out",
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": s.server,
                        "port": s.port,
                        "method": s.method,
                        "password": s.password
                    }]
                }
            }]
        }

    def render(self, p: Profile) -> str:
        if p.protocol == "vless-reality":
            return json.dumps(self._render_vless_reality(p), ensure_ascii=False, indent=2)
        elif p.protocol == "shadowsocks":
            return json.dumps(self._render_shadowsocks(p), ensure_ascii=False, indent=2)
        else:
            raise ValueError(f"Unsupported protocol {p.protocol}")

    def start_with_config(self) -> None:
        with self.lock:
            if self.current and self.current.started:
                logger.warning("Xray is already running.")
                return
        cfg = load_config()
        ensure_logs_dir(cfg)
        prepare_session(cfg)
        p = get_active_profile(cfg)
        self.start(p)

    def start(self, p: Profile):
        with self.lock:
            if self.current and self.current.started:
                logger.warning("Xray is already running.")
                return
            json_cfg = self.render(p)
            logger.info(f"Starting Xray with profile '{p.name}'")
            try:
                xray.startFromJSON(json_cfg)
                self.current = XrayInstance(json_cfg)
                self.current.started = True
                logger.info("Xray started successfully.")
            except (ConnectionError, TimeoutError) as e:
                logger.error(f"Failed to start Xray: {e}")
                raise
            except Exception as e:
                logger.error(f"Unexpected error during start: {e}")
                raise

    def stop(self):
        with self.lock:
            if not self.current or not self.current.started:
                logger.warning("Xray is not running.")
                return
            logger.info("Stopping Xray...")
            try:
                self.current = None
                logger.info("Xray stopped.")
            except Exception as e:
                logger.error(f"Failed to stop Xray: {e}")

    def stats(self, pattern: str = "", reset: bool = False) -> str:
        if not self.current or not self.current.started:
            logger.warning("Xray is not running. Cannot fetch stats.")
            return ""
        try:
            stats = xray.queryStats("127.0.0.1:10085", 1000, pattern, reset)
            if not stats:
                logger.info("No stats returned. Please check your policy.system configuration and traffic flow.")
            logger.info(f"Xray stats: {stats}")
            return stats
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"Failed to query Xray stats: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error fetching stats: {e}")
            raise

if __name__ == "__main__":
    eng = Engine()
    eng.start_with_config()
    try:
        print(eng.stats())
    finally:
        eng.stop()



