import json
import os
import time
import uuid
import threading
import re
from dataclasses import dataclass, asdict, field
from typing import List, Optional

APP_DIR = os.path.abspath(os.path.dirname(__file__))
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
_LOCK = threading.Lock()

_HEX_RE = re.compile(r"^[0-9a-f]{1,16}$", re.IGNORECASE)
_SS_METHODS = {"chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm"}
_ALLOWED_ALPN = {"h2", "http/1.1"}

@dataclass
class RealitySettings:
    server: str = ""
    port: int = 443
    sni: str = ""
    alpn: List[str] = field(default_factory=lambda: ["h2", "http/1.1"])
    public_key: str = ""
    short_id: str = field(default_factory=lambda: f"{uuid.uuid4().hex[:8]}")
    flow: str = "xtls-rprx-vision"
    user_id: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class ShadowsocksSettings:
    server: str = ""
    port: int = 443
    method: str = "chacha20-ietf-poly1305"
    password: str = ""

@dataclass
class Profile:
    name: str = "Default"
    protocol: str = "vless-reality"
    reality: Optional[RealitySettings] = field(default_factory=RealitySettings)
    shadowsocks: Optional[ShadowsocksSettings] = field(default_factory=ShadowsocksSettings)
    split_tunnel_apps: List[str] = field(default_factory=list)
    use_mesh: bool = True
    cname_endpoint: Optional[str] = None
    tls_alpn: List[str] = field(default_factory=lambda: ["h2", "http/1.1"])
    tls_server_name: Optional[str] = None
    is_active: bool = True

@dataclass
class RotationPolicy:
    short_id_interval_sec: int = 3600
    last_rotated: float = 0.0

@dataclass
class AppConfig:
    profiles: List[Profile] = field(default_factory=lambda: [Profile()])
    rotation: RotationPolicy = field(default_factory=RotationPolicy)
    logs_dir: str = os.path.join(APP_DIR, "logs")
    stun_servers: List[str] = field(default_factory=lambda: ["stun:stun.l.google.com:19302"])
    turn_server: Optional[str] = None
    turn_user: Optional[str] = None
    turn_pass: Optional[str] = None
    relay_enabled: bool = True
    signal_url: str = "http://127.0.0.1:8787"
    e2e_enabled: bool = True
    version: str = "1.0.0"

def _migrate_dict(d: dict) -> dict:
    ver = d.get("version", "1.0.0")
    profiles = d.get("profiles", [])
    for p in profiles:
        v = p.get("tls_alpn")
        if isinstance(v, str):
            p["tls_alpn"] = [x.strip() for x in v.split(",") if x.strip()]
        elif not isinstance(v, list) or not v:
            p["tls_alpn"] = ["h2", "http/1.1"]
        p.setdefault("is_active", True)
        if "reality" in p and isinstance(p["reality"], dict):
            if not isinstance(p["reality"].get("alpn"), list) or not p["reality"]["alpn"]:
                p["reality"]["alpn"] = ["h2", "http/1.1"]
    d["version"] = ver
    return d

def _validate_reality(r: RealitySettings) -> None:
    if not (1 <= int(r.port) <= 65535):
        raise ValueError(f"Reality port out of range: {r.port}")
    if r.short_id and not _HEX_RE.fullmatch(r.short_id):
        raise ValueError(f"Reality short_id must be hex up to 16 chars: {r.short_id}")
    try:
        uuid.UUID(str(r.user_id))
    except Exception:
        r.user_id = str(uuid.uuid4())
    if not isinstance(r.alpn, list):
        r.alpn = ["h2", "http/1.1"]
    else:
        norm = [a for a in r.alpn if isinstance(a, str) and a in _ALLOWED_ALPN]
        r.alpn = norm if norm else ["h2", "http/1.1"]
    if not isinstance(r.sni, str):
        r.sni = ""

def _validate_ss(s: ShadowsocksSettings) -> None:
    if not (1 <= int(s.port) <= 65535):
        raise ValueError(f"Shadowsocks port out of range: {s.port}")
    if s.method not in _SS_METHODS:
        s.method = "chacha20-ietf-poly1305"

def _atomic_write(path: str, data: str) -> None:
    tmp = f"{path}.tmp"
    bak = f"{path}.bak"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    if os.path.exists(path):
        try:
            with open(path, "rb") as src, open(bak, "wb") as dst:
                dst.write(src.read()); dst.flush(); os.fsync(dst.fileno())
        except Exception:
            pass
    os.replace(tmp, path)

def save_config(cfg: AppConfig) -> None:
    with _LOCK:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        os.makedirs(cfg.logs_dir, exist_ok=True)
        payload = json.dumps(asdict(cfg), ensure_ascii=False, indent=2)
        _atomic_write(CONFIG_PATH, payload)

def load_config() -> AppConfig:
    with _LOCK:
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            bak = CONFIG_PATH + ".bak"
            if os.path.exists(bak):
                with open(bak, "r", encoding="utf-8") as f:
                    d = json.load(f)
            else:
                d = asdict(AppConfig())
        d = _migrate_dict(d)

        def to_profile(p: dict) -> Profile:
            pr = Profile(**{k: v for k, v in p.items() if k not in ("reality", "shadowsocks")})
            if p.get("reality"):
                pr.reality = RealitySettings(**p["reality"])
            if p.get("shadowsocks"):
                pr.shadowsocks = ShadowsocksSettings(**p["shadowsocks"])
            pr.tls_alpn = [a for a in (pr.tls_alpn or []) if a in _ALLOWED_ALPN] or ["h2", "http/1.1"]
            return pr

        cfg = AppConfig(
            profiles=[to_profile(p) for p in d.get("profiles", [])],
            rotation=RotationPolicy(**d.get("rotation", {})),
            logs_dir=d.get("logs_dir", os.path.join(APP_DIR, "logs")),
            stun_servers=d.get("stun_servers", ["stun:stun.l.google.com:19302"]),
            turn_server=d.get("turn_server"),
            turn_user=d.get("turn_user"),
            turn_pass=d.get("turn_pass"),
            relay_enabled=d.get("relay_enabled", True),
            signal_url=d.get("signal_url", "http://127.0.0.1:8787"),
            e2e_enabled=d.get("e2e_enabled", True),
            version=d.get("version", "1.0.0"),
        )

        for p in cfg.profiles:
            if p.reality:
                _validate_reality(p.reality)
                p.tls_alpn = [a for a in (p.tls_alpn or []) if a in _ALLOWED_ALPN] or ["h2", "http/1.1"]
                p.reality.alpn = [a for a in (p.reality.alpn or []) if a in _ALLOWED_ALPN] or ["h2", "http/1.1"]
            if p.shadowsocks:
                _validate_ss(p.shadowsocks)

        return cfg

# --------------------- short_id ротация ---------------------
import requests

def _fetch_shortid_pool(base_url: str, timeout: float = 5.0) -> List[str]:
    try:
        resp = requests.get(f"{base_url}/shortid_pool", timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        raw_pool = data.get("short_ids", []) if isinstance(data, dict) else []
        return [sid for sid in raw_pool if isinstance(sid, str) and _HEX_RE.fullmatch(sid)]
    except Exception as e:
        print(f"[MiniVPN] failed to fetch short_id pool: {e}")
        return []

def maybe_rotate_short_id(cfg: AppConfig, signal_url: Optional[str] = None) -> None:
    with _LOCK:
        now = time.time()
        if now - cfg.rotation.last_rotated < cfg.rotation.short_id_interval_sec:
            return
        base_url = signal_url or cfg.signal_url or "http://127.0.0.1:8787"
        pool = _fetch_shortid_pool(base_url)
        if not pool:
            cfg.rotation.last_rotated = now
            save_config(cfg)
            return
        import random
        for p in cfg.profiles:
            if p.protocol == "vless-reality" and p.reality:
                old_id = p.reality.short_id or ""
                new_id = random.choice(pool)
                if new_id != old_id:
                    p.reality.short_id = new_id
                    print(f"[MiniVPN] rotated short_id for '{p.name}': {old_id} -> {new_id}")
        cfg.rotation.last_rotated = now
        save_config(cfg)

def force_rotate_short_id(cfg: AppConfig, signal_url: Optional[str] = None) -> None:
    with _LOCK:
        base_url = signal_url or cfg.signal_url or "http://127.0.0.1:8787"
        pool = _fetch_shortid_pool(base_url)
        if not pool:
            return
        import random
        for p in cfg.profiles:
            if not p.is_active:
                continue
            if p.protocol == "vless-reality" and p.reality:
                old_id = p.reality.short_id or ""
                new_id = random.choice(pool)
                if new_id != old_id:
                    p.reality.short_id = new_id
                    print(f"[MiniVPN] force-rotated short_id for '{p.name}': {old_id} -> {new_id}")
        save_config(cfg)

def prepare_session(cfg: AppConfig, signal_url: Optional[str] = None) -> None:
    with _LOCK:
        force_rotate_short_id(cfg, signal_url=signal_url)
        changed = False
        for p in cfg.profiles:
            if p.protocol == "vless-reality" and p.reality:
                new_tls = [a for a in (p.tls_alpn or []) if a in _ALLOWED_ALPN] or ["h2", "http/1.1"]
                new_rel = [a for a in (p.reality.alpn or []) if a in _ALLOWED_ALPN] or ["h2", "http/1.1"]
                if new_tls != p.tls_alpn or new_rel != p.reality.alpn:
                    p.tls_alpn = new_tls
                    p.reality.alpn = new_rel
                    changed = True
        if changed:
            save_config(cfg)

def get_active_profile(cfg: AppConfig) -> Profile:
    for p in cfg.profiles:
        if getattr(p, "is_active", False):
            return p
    return cfg.profiles

def ensure_logs_dir(cfg: AppConfig) -> None:
    os.makedirs(cfg.logs_dir, exist_ok=True)

if __name__ == "__main__":
    cfg = load_config()
    ensure_logs_dir(cfg)
    prepare_session(cfg)
    p = get_active_profile(cfg)
    print("Active profile:", p.name, "short_id:", p.reality.short_id if p.reality else "N/A")
    print("ALPN (profile):", p.tls_alpn, "ALPN (reality):", p.reality.alpn if p.reality else [])
    print("Signal URL:", cfg.signal_url)

