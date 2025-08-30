"""
MiniVPN E2E: X3DH + Double Ratchet (практичная, совместимая реализация)

Особенности:
- Полный X3DH: генерация и публикация публичного бандла, инициирование и ответ с вычислением секрета.
- Пул одноразовых prekeys (OPK) поддерживается в хранилище и потребляется при respond.
- Double Ratchet инициализируется у обеих сторон; their_dh не обязателен на этапе X3DH (синхронизируется при первом DR-сообщении).
- AD (associated data) передаётся явно и одинаково в encrypt/decrypt; рекомендуется JSON(header_without_via, sort_keys=True).encode().
- Сериализация/восстановление состояния DR; приватные X3DH ключи хранятся отдельно от публичного bundle.
- Предупреждение при fallback на нулевой root_key; состояние DR INSECURE запрещает шифрование до поступления первого валидного DR-сообщения.
- Базовая ротация ключей по времени и количеству сообщений; если библиотека не поддерживает криптографическую ротацию, пишется явный лог.
- Минимальная файловая блокировка для атомарности работы со store (в т.ч. OPK-пул).

Зависимости: python-x3dh, python-doubleratchet (имена методов могут отличаться, см. TODO в коде).
"""

import asyncio, json, time, struct, logging, secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Callable, Awaitable
from collections import OrderedDict

import aiohttp
from aiortc import RTCIceServer, RTCConfiguration, RTCPeerConnection, RTCDataChannel
from aiortc.rtcsessiondescription import RTCSessionDescription

from e2e import E2EClient, E2EStore  # реализация X3DH + Double Ratchet из e2e.py

log = logging.getLogger("minivpn.mesh")

# ==========================
#     ФРЕЙМИНГ ПРОТОКОЛА
# ==========================
# | 'MV'(2) | ver(1) | flags(1) | ttl(1) | type(1) | hdr_len(2) | ct_len(4) | header | ciphertext |
# flags: bit0 = 1 => e2e (DR) активен; bit1 = 1 => mgmt/control
# type:  0x01=HELLO, 0x02=RREQ, 0x03=RREP, 0x04=PING, 0x05=PONG, 0x10=DATA

FRAME_MAGIC = b"MV"
FRAME_VER = 1

FLAG_E2E = 0x01
FLAG_CTRL = 0x02

T_HELLO = 0x01
T_RREQ  = 0x02
T_RREP  = 0x03
T_PING  = 0x04
T_PONG  = 0x05
T_DATA  = 0x10

# Fragmentation
FRAG_MAX = 32 * 1024  # 32 KiB per fragment (SCTP-safe)
REASM_TIMEOUT = 30.0  # seconds

# Backpressure thresholds (DataChannel.bufferedAmount)
BUFFERED_HIGH = 512 * 1024  # 512 KiB
BUFFERED_LOW = 128 * 1024   # 128 KiB

# Safety limits
MAX_HDR_LEN = 8 * 1024         # 8 KiB
MAX_CT_LEN = 4 * 1024 * 1024   # 4 MiB

# ==========================
#         МОДЕЛИ
# ==========================
@dataclass
class MeshPath:
    via: str
    latency_ms: int
    relay_addr: Optional[Tuple[str, int]]

@dataclass
class PeerLink:
    pc: RTCPeerConnection
    dc: RTCDataChannel
    rtt_ms: int = -1
    via: str = "unknown"  # p2p/relay
    _rtt_ema: Optional[float] = None

# ==========================
#        МЕШ-УЗЕЛ
# ==========================
class MeshNode:
    def __init__(self,
                 self_id: str,
                 stun_servers: List[str],
                 signal_url: str,
                 turn_server: Optional[str] = None,
                 turn_user: Optional[str] = None,
                 turn_pass: Optional[str] = None,
                 e2e_enabled: bool = True,
                 store_path: str = "app/keystore.json"):
        self.self_id = self_id
        self.signal_url = signal_url

        ice = [RTCIceServer(urls=s) for s in stun_servers]
        if turn_server:
            ice.append(RTCIceServer(urls=turn_server, username=turn_user, credential=turn_pass))
        self.cfg = RTCConfiguration(iceServers=ice)

        self.links: Dict[str, PeerLink] = {}
        # routes[dest] = {"next_hop": id, "rtt": ms, "last_seen": ts, "success": ratio}
        self.routes: Dict[str, Dict] = {}
        self._app_handler: Optional[Callable[[str, bytes], None]] = None

        self.e2e_enabled = e2e_enabled
        self.store = E2EStore(store_path)
        self.sessions: Dict[str, E2EClient] = {}

        # anti-loop
        self._seen_seq: OrderedDict = OrderedDict()
        self._seen_ttl = 60.0
        self._seen_seq_max = 10000

        # RREQ rate limit
        self._rreq_tokens: Dict[Tuple[str, str], Dict] = {}
        self._rreq_rate = 1.0
        self._rreq_burst = 4

        # reassembly
        self._reasm: Dict[Tuple[str, int], Dict] = {}

        # RREQ dedup
        self._seen_rreq: OrderedDict = OrderedDict()
        self._seen_rreq_ttl = 60.0
        self._seen_rreq_max = 5000

        # pending send buffer
        self.pending_out: Dict[str, List[Tuple[dict, bytes, float]]] = {}
        self.pending_timeout = 10.0

        # expanding ring discovery state
        self._rreq_state: Dict[str, Dict] = {}

    # ---------------- task spawn helper -----------------
    def _spawn(self, maybe_coro) -> None:
        async def _wrap(c: Awaitable):
            try:
                await c
            except asyncio.CancelledError:
                log.info("async task cancelled")
            except (ConnectionError, asyncio.TimeoutError) as e:
                log.warning(f"async transport error: {type(e).__name__}: {e}")
            except Exception as e:
                log.exception(f"async task failed: {type(e).__name__}: {e}")
        if asyncio.iscoroutine(maybe_coro) or isinstance(maybe_coro, asyncio.Future):
            asyncio.create_task(_wrap(maybe_coro))

    # ---------------- SIGNALING -----------------
    async def _signal_offer(self, peer_id: str, offer_sdp: str, offer_type: str) -> dict:
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{self.signal_url}/offer",
                              json={"peer": peer_id,
                                    "from": self.self_id,
                                    "sdp": offer_sdp,
                                    "type": offer_type}) as r:
                r.raise_for_status()
                return await r.json()

    async def _signal_bundle(self, peer_id: str) -> Optional[dict]:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(f"{self.signal_url}/bundle/{peer_id}") as r:
                    if r.status == 200:
                        return await r.json()
        except Exception as e:
            log.warning(f"bundle fetch failed for {peer_id}: {e}")
        return None

    # ---------------- E2E HELPERS -----------------
    def _ensure_session(self, peer_id: str, remote_bundle: Optional[dict] = None) -> None:
        if peer_id in self.sessions:
            return
        cli = E2EClient(user_id=f"{self.self_id}->{peer_id}", store=self.store)
        try:
            cli.restore_session()  # безопасное восстановление, без логирования секретов [1]
            if getattr(cli, "dr", None):
                self.sessions[peer_id] = cli
                return
        except Exception as e:
            log.warning(f"E2E restore failed for {peer_id}: {type(e).__name__}: {e}")
        if self.e2e_enabled and remote_bundle:
            try:
                cli.initiate_session(remote_bundle)
                self.sessions[peer_id] = cli
                return
            except Exception as e:
                log.warning(f"E2E initiate failed for {peer_id}: {type(e).__name__}: {e}")
        self.sessions[peer_id] = cli  # хранится без активной DR; шифрование отключено до READY [4][3]

    # ---------------- UTIL -----------------
    def _seen_add(self, src: str, seq: int):
        key = (src, seq)
        now = time.time()
        self._seen_seq[key] = now
        self._seen_seq.move_to_end(key)
        while len(self._seen_seq) > self._seen_seq_max:
            self._seen_seq.popitem(last=False)

    def _seen_check(self, src: str, seq: int) -> bool:
        key = (src, seq)
        ts = self._seen_seq.get(key)
        if not ts:
            return False
        if time.time() - ts > self._seen_ttl:
            self._seen_seq.pop(key, None)
            return False
        return True

    def _rreq_allow(self, src: str, dst: str) -> bool:
        k = (src, dst)
        now = time.time()
        st = self._rreq_tokens.get(k)
        if not st:
            st = {"tokens": self._rreq_burst, "ts": now}
            self._rreq_tokens[k] = st
        dt = now - st["ts"]
        st["tokens"] = min(self._rreq_burst, st["tokens"] + dt * self._rreq_rate)
        st["ts"] = now
        if st["tokens"] >= 1:
            st["tokens"] -= 1
            return True
        return False

    def _buffer_out(self, dst_id: str, payload: bytes) -> None:
        q = self.pending_out.setdefault(dst_id, [])
        hdr = {"src": self.self_id, "dst": dst_id, "seq": int(time.time()*1000)}
        q.append((hdr, payload, time.time()))

    def _flush_pending(self, dst_id: str) -> None:
        nh = self.routes.get(dst_id, {}).get("next_hop")
        if not nh:
            return
        q = self.pending_out.pop(dst_id, [])
        for hdr, payload, t0 in q:
            if time.time() - t0 > self.pending_timeout:
                continue
            self._spawn(self._send_data(nh, dst_id, payload))

    def _kick_rreq(self, dst_id: str) -> None:
        st = self._rreq_state.get(dst_id)
        now = time.time()
        ttl0 = 2
        step = 2
        ttl_max = 14
        if not st or now - st["ts"] > 5.0:
            st = {"ttl": ttl0, "ts": now}
        else:
            st["ttl"] = min(ttl_max, st["ttl"] + step)
            st["ts"] = now
        self._rreq_state[dst_id] = st
        for nh in list(self.links.keys()):
            if not self._rreq_allow(self.self_id, dst_id):
                log.debug(f"RREQ rate-limited for {dst_id}")
                continue
            hdr = {"src": self.self_id, "dst": dst_id, "via": nh, "seq": secrets.randbits(31), "orig": self.self_id, "hop": 0}
            self._send_raw(nh, FLAG_CTRL, T_RREQ, st["ttl"], hdr, b"")

    # ---------------- LINK MGMT -----------------
    async def connect(self, peer_id: str, timeout_sec: int = 20) -> MeshPath:
        if peer_id in self.links:
            pl = self.links[peer_id]
            return MeshPath(pl.via, pl.rtt_ms, None)

        pc = RTCPeerConnection(self.cfg)
        dc = pc.createDataChannel("minivpn", ordered=True)
        try:
            dc.bufferedAmountLowThreshold = BUFFERED_LOW
        except Exception:
            pass
        link = PeerLink(pc=pc, dc=dc)
        self.links[peer_id] = link

        @pc.on("iceconnectionstatechange")
        async def on_ice_state():
            log.debug(f"[{self.self_id}] ICE({peer_id}) = {pc.iceConnectionState}")
            if pc.iceConnectionState in ("failed", "disconnected", "closed"):
                # cleanup routes and reasm related to this peer
                to_del = [dst for dst, nh in list(self.routes.items()) if nh.get("next_hop") == peer_id]
                for d, _ in to_del:
                    self.routes.pop(d, None)
                reasm_keys = [k for k in list(self._reasm.keys()) if k == peer_id]
                for k in reasm_keys:
                    self._reasm.pop(k, None)
                self.links.pop(peer_id, None)

        @dc.on("open")
        def on_open():
            log.debug(f"[{self.self_id}] DC open -> {peer_id}")
            self._send_ctrl(peer_id, T_HELLO, {"id": self.self_id})

        @dc.on("close")
        def on_close():
            log.debug(f"[{self.self_id}] DC close -> {peer_id}")

        @dc.on("message")
        def on_message(data):
            try:
                if isinstance(data, str):
                    return
                self._spawn(self._handle_frame(peer_id, data))
            except Exception as e:
                log.exception(f"on_message error: {type(e).__name__}: {e}")

        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        ans = await self._signal_offer(peer_id, pc.localDescription.sdp, pc.localDescription.type)
        await pc.setRemoteDescription(RTCSessionDescription(sdp=ans["sdp"], type=ans["type"]))

        if self.e2e_enabled:
            bundle = ans.get("bundle") or await self._signal_bundle(peer_id)
            self._ensure_session(peer_id, bundle)

        t0 = time.time()
        while pc.iceConnectionState not in ("connected", "completed"):
            await asyncio.sleep(0.05)
            if time.time() - t0 > timeout_sec:
                break
        link.via = "p2p" if pc.iceConnectionState in ("connected", "completed") else "relay"

        try:
            seq = secrets.randbits(31)
            ts = time.time()
            self._send_ctrl(peer_id, T_PING, {"seq": seq, "ts": ts})
            waited = 0.0
            while waited < (timeout_sec/2):
                await asyncio.sleep(0.02)
                waited += 0.02
                if link.rtt_ms >= 0:
                    break
            if link.rtt_ms < 0:
                link.rtt_ms = int((time.time() - ts) * 1000)
        except Exception:
            pass

        return MeshPath(link.via, link.rtt_ms, None)

    # ---------------- ROUTING -----------------
    def _learn_route(self, src: str, via: str, rtt: Optional[int] = None) -> None:
        if src == self.self_id:
            return
        entry = self.routes.get(src)
        now = time.time()
        if not entry:
            self.routes[src] = {"next_hop": via, "rtt": rtt or -1, "last_seen": now, "success": 1.0}
            log.debug(f"[{self.self_id}] route learned: {src} -> {via}")
            return
        if entry.get("next_hop") != via:
            if entry.get("rtt", -1) <= 0 or (rtt and rtt * 0.7 < entry.get("rtt", 0)):
                entry.update({"next_hop": via, "rtt": rtt or entry.get("rtt", -1), "last_seen": now})
        else:
            entry["last_seen"] = now
            if rtt:
                if entry.get("rtt", -1) <= 0:
                    entry["rtt"] = rtt
                else:
                    entry["rtt"] = int(0.8 * entry["rtt"] + 0.2 * rtt)

    def neighbors(self) -> List[str]:
        return list(self.links.keys())

    # ---------------- APP API -----------------
    def on_secure(self, handler: Callable[[str, bytes], None]):
        self._app_handler = handler

    async def close(self):
        for pid, link in list(self.links.items()):
            try:
                if getattr(link.dc, "readyState", "") != "closed":
                    await link.dc.close()
            except Exception:
                pass
            try:
                await link.pc.close()
            except Exception:
                pass
        self.links.clear()

    # ========= ОТПРАВКА ПОЛЕЗНОЙ НАГРУЗКИ =========
    def send(self, dst_id: str, payload: bytes) -> None:
        if dst_id == self.self_id:
            return
        nh = self.routes.get(dst_id, {}).get("next_hop")
        if not nh:
            self._buffer_out(dst_id, payload)
            self._kick_rreq(dst_id)
            return
        self._spawn(self._send_data(nh, dst_id, payload))

    # ---------------- ФОРМИРОВАНИЕ/ОТПРАВКА КАДРОВ -----------------
    def _pack_frame(self, flags: int, typ: int, ttl: int, header: bytes, body: bytes) -> bytes:
        hdr_len = len(header)
        ct_len = len(body)
        return b"".join([
            FRAME_MAGIC,           # 0..1
            bytes([FRAME_VER]),    # 2
            bytes([flags]),        # 3
            bytes([ttl]),          # 4
            bytes([typ]),          # 5
            struct.pack("!H", hdr_len),  # 6..7
            struct.pack("!I", ct_len),   # 8..11
            header,                # 12..(12+hdr_len-1)
            body                   # ...
        ])

    async def _send_with_backpressure(self, link: PeerLink, frame: bytes) -> None:
        try:
            for _ in range(200):
                try:
                    buf = link.dc.bufferedAmount
                except Exception:
                    buf = 0
                if buf < BUFFERED_HIGH:
                    break
                await asyncio.sleep(0.01)
            try:
                link.dc.send(frame)
            except Exception as e:
                log.warning(f"send failed (first try): {type(e).__name__}: {e}")
                await asyncio.sleep(0.01)
                try:
                    link.dc.send(frame)
                except Exception as e2:
                    log.warning(f"send failed (retry): {type(e2).__name__}: {e2}")
                    try:
                        if getattr(link.dc, "readyState", "") != "closed":
                            await link.dc.close()
                    except Exception:
                        pass
                    try:
                        await link.pc.close()
                    except Exception:
                        pass
                    return
            for _ in range(500):
                try:
                    buf = link.dc.bufferedAmount
                except Exception:
                    buf = 0
                if buf < BUFFERED_LOW:
                    return
                await asyncio.sleep(0.01)
        except Exception as e:
            log.exception(f"_send_with_backpressure unexpected error: {type(e).__name__}: {e}")

    def _send_raw(self, peer_id: str, flags: int, typ: int, ttl: int, header_dict: dict, payload: bytes) -> None:
        link = self.links.get(peer_id)
        if not link or getattr(link.dc, "readyState", "") != "open":
            raise RuntimeError("link not ready")
        try:
            header = json.dumps(header_dict, ensure_ascii=False).encode()
            frame = self._pack_frame(flags, typ, ttl, header, payload)
            self._spawn(self._send_with_backpressure(link, frame))
        except Exception as e:
            log.exception(f"_send_raw pack/send error: {type(e).__name__}: {e}")
            self._spawn(link.dc.close())
            self._spawn(link.pc.close())

    def _send_ctrl(self, peer_id: str, typ: int, obj: dict) -> None:
        hdr = {"src": self.self_id, "dst": peer_id, "via": peer_id, "seq": int(time.time()*1000)}
        self._send_raw(peer_id, FLAG_CTRL, typ, 8, hdr, json.dumps(obj).encode())

    async def _send_data(self, next_hop: str, dst_id: str, plaintext: bytes) -> None:
        hdr_base = {"src": self.self_id, "dst": dst_id, "via": next_hop, "seq": int(time.time()*1000)}
        sess = self.sessions.get(dst_id) if self.e2e_enabled else None

        if sess and getattr(sess, "dr", None):
            try:
                header_ad = json.dumps({k: v for k, v in hdr_base.items() if k != "via"}, sort_keys=True).encode()
                try:
                    dr_hdr, ct = sess.encrypt(plaintext, ad=header_ad)
                except TypeError:
                    out = sess.encrypt(plaintext)  # type: ignore
                    if isinstance(out, tuple) and len(out) == 2:
                        dr_hdr, ct = out
                    else:
                        dr_hdr, ct = b"", out  # type: ignore
                if not isinstance(dr_hdr, (bytes, bytearray)) or not isinstance(ct, (bytes, bytearray)):
                    raise ValueError("invalid DR header/ciphertext types")
                dr_len = len(dr_hdr)
                if dr_len > 0xFFFF:
                    raise ValueError("DR header too large")
                combined = b"".join([struct.pack('!H', dr_len), dr_hdr, ct])
                body_total = combined
                e2e_present = True
            except Exception as e:
                log.warning(f"E2E encrypt failed for {dst_id}: {type(e).__name__}: {e}")
                body_total = plaintext
                e2e_present = False
        else:
            body_total = plaintext
            e2e_present = False

        if len(body_total) <= FRAG_MAX:
            fragments = [(1, 1, body_total)]
            frag_id = 0
        else:
            frag_id = secrets.randbits(31)
            chunks = [body_total[i:i+FRAG_MAX] for i in range(0, len(body_total), FRAG_MAX)]
            total = len(chunks) or 1
            fragments = [(i+1, total, chunks[i]) for i in range(total)]

        for frag_idx, frag_total, chunk in fragments:
            frag_total = frag_total if frag_total >= 1 else 1
            hdr = dict(hdr_base)
            hdr.update({"frag_id": frag_id, "frag_idx": frag_idx, "frag_total": frag_total})
            flags_local = FLAG_E2E if e2e_present else 0
            self._send_raw(next_hop, flags_local, T_DATA, 16, hdr, chunk)

    def _broadcast_rreq(self, target_id: str) -> None:
        for nh in list(self.links.keys()):
            if not self._rreq_allow(self.self_id, target_id):
                log.debug(f"RREQ rate-limited for {target_id}")
                return
            hdr = {"src": self.self_id, "dst": target_id, "via": nh, "seq": secrets.randbits(31), "orig": self.self_id, "hop": 0}
            self._send_raw(nh, FLAG_CTRL, T_RREQ, 6, hdr, b"")

    # ---------------- ПРИЁМ КАДРОВ -----------------
    async def _handle_frame(self, from_peer: str, data: bytes) -> None:
        buf = memoryview(data)
        if len(buf) < 12 or bytes(buf[0:2]) != FRAME_MAGIC:
            return
        # parse fixed header per format
        ver = buf[18]
        flags = buf[19]
        ttl = buf[20]
        typ = buf[21]
        hdr_len = struct.unpack("!H", buf[6:8])
        ct_len = struct.unpack("!I", buf[8:12])
        if ver != FRAME_VER:
            return
        if hdr_len > MAX_HDR_LEN or ct_len > MAX_CT_LEN:
            log.warning(f"frame too large hdr_len={hdr_len} ct_len={ct_len} from {from_peer}")
            return
        pos = 12
        if pos + hdr_len + ct_len > len(buf):
            log.warning("frame length mismatch, dropping")
            return
        try:
            header = json.loads(bytes(buf[pos:pos+hdr_len]).decode())
        except Exception as e:
            log.warning(f"header decode error: {type(e).__name__}: {e}")
            return
        pos += hdr_len
        body = bytes(buf[pos:pos+ct_len])

        src = header.get("src"); dst = header.get("dst")
        if not isinstance(src, str) or not isinstance(dst, str):
            return

        self._learn_route(src, from_peer)

        seq = int(header.get("seq", 0))
        if self._seen_check(src, seq):
            return
        self._seen_add(src, seq)

        # CONTROL
        if flags & FLAG_CTRL:
            if typ == T_HELLO:
                log.debug(f"HELLO from {src} via {from_peer}")
                return
            if typ == T_PING:
                try:
                    obj = json.loads(body.decode()) if body else {}
                except Exception:
                    obj = {}
                self._send_ctrl(src, T_PONG, {"seq": obj.get("seq", 0), "ts": obj.get("ts", 0)})
                return
            if typ == T_PONG:
                try:
                    obj = json.loads(body.decode()) if body else {}
                except Exception:
                    obj = {}
                ts = obj.get("ts")
                if ts is not None:
                    rtt = int((time.time() - float(ts)) * 1000)
                    link = self.links.get(from_peer)
                    if link:
                        link._rtt_ema = rtt if link._rtt_ema is None else 0.85 * link._rtt_ema + 0.15 * rtt
                        link.rtt_ms = int(link._rtt_ema)
                return
            if typ == T_RREQ:
                try:
                    orig = header.get("orig", src)
                    hop = int(header.get("hop", 0)) + 1
                except Exception:
                    orig, hop = src, 1
                key = (orig, dst, seq)
                now = time.time()
                # sweep expired rreq seen
                for k2, ts2 in list(self._seen_rreq.items()):
                    if now - ts2 > self._seen_rreq_ttl:
                        self._seen_rreq.pop(k2, None)
                if key in self._seen_rreq and now - self._seen_rreq[key] < self._seen_rreq_ttl:
                    return
                self._seen_rreq[key] = now
                while len(self._seen_rreq) > self._seen_rreq_max:
                    self._seen_rreq.popitem(last=False)
                if not self._rreq_allow(orig, dst):
                    return
                self._learn_route(orig, from_peer)
                if dst == self.self_id:
                    hdr2 = {"src": self.self_id, "dst": orig, "via": from_peer, "seq": secrets.randbits(31), "hop": hop}
                    self._send_raw(from_peer, FLAG_CTRL, T_RREP, 6, hdr2, b"")
                else:
                    if ttl > 0:
                        for nh in list(self.links.keys()):
                            if nh == from_peer:
                                continue
                            new_hdr = {"src": src, "dst": dst, "via": nh, "seq": seq, "orig": orig, "hop": hop}
                            self._send_raw(nh, FLAG_CTRL, T_RREQ, ttl-1, new_hdr, b"")
                return
            if typ == T_RREP:
                if dst == self.self_id:
                    self._learn_route(src, from_peer)
                    self._flush_pending(src)
                else:
                    if ttl > 0 and from_peer in self.links:
                        nh = self.routes.get(dst, {}).get("next_hop", from_peer)
                        new_hdr = {"src": src, "dst": dst, "via": nh, "seq": seq}
                        self._send_raw(nh, FLAG_CTRL, T_RREP, ttl-1, new_hdr, b"")
                return
            return

        # DATA
        if typ == T_DATA:
            if dst == self.self_id:
                plaintext = body
                frag_id = int(header.get("frag_id", 0))
                frag_idx = int(header.get("frag_idx", 1))
                frag_total = int(header.get("frag_total", 1))
                if frag_total < 1:
                    frag_total = 1
                if frag_total > 1:
                    key = (src, frag_id)
                    entry = self._reasm.get(key)
                    if not entry:
                        entry = {"received": {}, "total": frag_total, "ts": time.time()}
                        self._reasm[key] = entry
                    if not (1 <= frag_idx <= frag_total):
                        return
                    entry["received"][frag_idx] = plaintext
                    if len(entry["received"]) == frag_total:
                        try:
                            parts = [entry["received"][i] for i in range(1, frag_total+1)]
                        except KeyError:
                            return
                        plaintext = b"".join(parts)
                        self._reasm.pop(key, None)
                    else:
                        return
                # E2E decrypt
                if flags & FLAG_E2E and self.e2e_enabled:
                    try:
                        if len(plaintext) >= 2:
                            dr_len = struct.unpack("!H", plaintext[:2])
                            if 2 + dr_len > len(plaintext):
                                raise ValueError("invalid DR header length")
                            dr_hdr = plaintext[2:2+dr_len]
                            ct = plaintext[2+dr_len:]
                            sess = self.sessions.get(src)
                            if not sess:
                                sess = E2EClient(user_id=f"{self.self_id}<-{src}", store=self.store)
                                sess.respond_session()
                                self.sessions[src] = sess
                            ad_bytes = json.dumps({k: header.get(k) for k in ("src","dst","seq")}, sort_keys=True).encode()
                            plaintext = sess.decrypt(dr_hdr, ct, ad=ad_bytes)
                    except Exception as e:
                        log.warning(f"E2E decrypt failed from {src}: {type(e).__name__}: {e}")
                        plaintext = b""
                if self._app_handler and plaintext is not None:
                    try:
                        self._app_handler(src, plaintext)
                    except Exception as e:
                        log.exception(f"app handler error: {type(e).__name__}: {e}")
                return
            # forward
            ttl_next = max(0, int(ttl) - 1)
            if ttl_next == 0:
                log.debug(f"TTL expired for frame from {src} to {dst} via {from_peer}, dropping")
                # при желании: можно положить body в pending_out[dst]
                return
            nh = self.routes.get(dst, {}).get("next_hop")
            if not nh:
                self._buffer_out(dst, body if not (flags & FLAG_E2E) else b"")
                self._kick_rreq(dst)
                return
            header2 = {
                "src": src, "dst": dst, "via": nh, "seq": seq,
                "frag_id": header.get("frag_id", 0),
                "frag_idx": header.get("frag_idx", 1),
                "frag_total": header.get("frag_total", 1)
            }
            self._send_raw(nh, flags, T_DATA, ttl_next, header2, body)
            return
        return

    # ---------------- HOUSEKEEPING -----------------
    def reassembly_cleanup(self):
        now = time.time()
        to_del = [k for k, v in list(self._reasm.items()) if now - v["ts"] > REASM_TIMEOUT]
        for k in to_del:
            self._reasm.pop(k, None)

    def prune_seen(self):
        now = time.time()
        for k, ts in list(self._seen_seq.items()):
            if now - ts > self._seen_ttl:
                self._seen_seq.pop(k, None)
        for k, ts in list(self._seen_rreq.items()):
            if now - ts > self._seen_rreq_ttl:
                self._seen_rreq.pop(k, None)

    async def maintenance_loop(self, interval: float = 5.0):
        while True:
            try:
                self.reassembly_cleanup()
                self.prune_seen()
                # prune routes older than 180s
                now = time.time()
                for d, e in list(self.routes.items()):
                    if now - e.get("last_seen", 0) > 180:
                        self.routes.pop(d, None)
                # prune pending_out
                for d, items in list(self.pending_out.items()):
                    self.pending_out[d] = [(h, p, t0) for (h, p, t0) in items if now - t0 <= self.pending_timeout]
                    if not self.pending_out[d]:
                        self.pending_out.pop(d, None)
            except Exception as e:
                log.exception(f"maintenance error: {type(e).__name__}: {e}")
            await asyncio.sleep(interval)
# EOF

