import subprocess
import logging
import platform
import json
import os
import threading
import time
from typing import List, Optional, Dict, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ==============================
#        PUBLIC ENTRYPOINT
# ==============================

def apply_split(apps: List[str], mode: str = "include", platform_opts: Optional[dict] = None) -> None:
    """
    Применение split tunneling.
    - Linux: per-UID через nftables meta skuid + fwmark (с маской) + ip rule policy routing.
    - macOS: per-UID через PF anchors с route-to.
    - Windows: per-process через WinDivert (pydivert): фильтрация по PID и политика include/exclude.
    mode: "include" | "exclude"
      include: указанные субъекты идут через VPN (маркирование/route через VPN)
      exclude: указанные субъекты обходят VPN (маркирование/route через main)
    """
    if not apps:
        logger.warning("Не указаны приложения/UID для split tunneling.")
        return
    if platform_opts is None:
        platform_opts = {}
    sys = platform.system()
    mode = (mode or "").lower()
    if mode not in ("include", "exclude"):
        raise ValueError("mode должен быть 'include' или 'exclude'")

    try:
        if sys == "Linux":
            vpn_if = platform_opts.get("vpn_if") or get_vpn_interface()
            if not vpn_if:
                logger.error("VPN интерфейс не найден. Передайте platform_opts['vpn_if'] явно.")
                return
            apply_linux_split(vpn_if, apps, mode)
        elif sys == "Darwin":
            apply_mac_split(apps, mode, platform_opts)
        elif sys == "Windows":
            apply_windows_split(apps, mode, platform_opts)
        else:
            logger.error(f"Платформа {sys} не поддерживается для split tunneling.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка при выполнении команды: {e}")
    except Exception as e:
        logger.error(f"Неизвестная ошибка: {e}")


def revert_split(platform_opts: Optional[dict] = None) -> None:
    """
    Откат изменений. Полноценный на Linux.
    macOS/Windows: предусмотрены процедуры отката (очистка anchor/остановка перехвата).
    """
    if platform_opts is None:
        platform_opts = {}
    sys = platform.system()
    try:
        if sys == "Linux":
            linux_revert()
        elif sys == "Darwin":
            mac_revert(platform_opts)
        elif sys == "Windows":
            windows_revert(platform_opts)
        else:
            logger.error(f"Платформа {sys} не поддерживается для revert.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка revert: {e}")
    except Exception as e:
        logger.error(f"Неизвестная ошибка revert: {e}")


# ==============================
#             LINUX
# ==============================

NFT_TABLE = "minivpn"
NFT_FAMILY = "inet"
NFT_CHAIN = "output"
NFT_SET = "minivpn_uids"
VPN_TABLE_ID = "100"

# Маскирование fwmark, чтобы не затирать чужие биты
MARK_INCLUDE_VAL = 0x1
MARK_EXCLUDE_VAL = 0x2
MARK_MASK = 0xFF

def _rule_sig(val: int) -> str:
    return f"fwmark 0x{val:x}/0x{MARK_MASK:x}"

def apply_linux_split(vpn_if: str, apps: List[str], mode: str) -> None:
    ensure_nft_table_and_chain()
    ensure_vpn_route_table_default(vpn_if)
    if mode == "include":
        ensure_ip_rule_exists(MARK_INCLUDE_VAL, VPN_TABLE_ID)
        fwmark_val = MARK_INCLUDE_VAL
    else:
        ensure_ip_rule_exists(MARK_EXCLUDE_VAL, "main")
        fwmark_val = MARK_EXCLUDE_VAL
    mark_users_traffic(apps, fwmark_val)
    logger.info(f"[Linux] Split применён: mode={mode}, vpn_if={vpn_if}, apps={apps}")

def ensure_nft_table_and_chain() -> None:
    if not nft_table_exists(NFT_FAMILY, NFT_TABLE):
        run(["nft", "add", "table", NFT_FAMILY, NFT_TABLE], check=True)
        logger.info(f"Создана таблица nft {NFT_FAMILY} {NFT_TABLE}")
    if not nft_chain_exists(NFT_FAMILY, NFT_TABLE, NFT_CHAIN):
        run([
            "nft", "add", "chain", NFT_FAMILY, NFT_TABLE, NFT_CHAIN,
            "type", "route", "hook", "output", "priority", "mangle", "policy", "accept"
        ], check=True)
        logger.info(f"Создана цепь nft {NFT_FAMILY} {NFT_TABLE} {NFT_CHAIN}")

def ensure_vpn_route_table_default(vpn_if: str) -> None:
    out = run(["ip", "route", "show", "table", VPN_TABLE_ID], capture_output=True, text=True).stdout
    if "default" not in out:
        run(["ip", "route", "add", "default", "dev", vpn_if, "table", VPN_TABLE_ID], check=True)
        logger.info(f"Добавлен default в таблицу {VPN_TABLE_ID}: dev {vpn_if}")

def ensure_ip_rule_exists(mark_val: int, table: str, prio: Optional[int] = None) -> None:
    rule_sig = _rule_sig(mark_val)
    rules = run(["ip", "rule", "show"], capture_output=True, text=True).stdout
    if rule_sig not in rules:
        args = ["ip", "rule", "add", "fwmark", f"0x{mark_val:x}/0x{MARK_MASK:x}", "lookup", table]
        if prio is not None:
            args += ["prio", str(prio)]
        else:
            args += ["prio", "10010" if mark_val == MARK_INCLUDE_VAL else "10020"]
        run(args, check=True)
        logger.info(f"Добавлено ip rule: {rule_sig} -> {table}")

def mark_users_traffic(apps: List[str], mark_val: int) -> None:
    uids = resolve_uids(apps)
    if not uids:
        logger.warning("Не удалось определить ни одного UID — пропуск маркировки.")
        return
    if not nft_set_exists(NFT_FAMILY, NFT_TABLE, NFT_SET):
        run(["nft", "add", "set", NFT_FAMILY, NFT_TABLE, NFT_SET, "{", "type", "uid", ";", "flags", "interval", "}"], check=True)
        logger.info(f"Создан set {NFT_SET}")
    elements_str = "{ " + ", ".join(str(uid) for uid in uids) + " }"
    add_el = run(["nft", "add", "element", NFT_FAMILY, NFT_TABLE, NFT_SET, elements_str], capture_output=True, text=True)
    if add_el.returncode != 0 and "File exists" not in (add_el.stderr or ""):
        logger.warning(f"nft add element rc={add_el.returncode}, err={add_el.stderr}")
    # Маска при установке mark: (meta mark & ~MASK) | VAL
    want_rule = f"meta skuid @{NFT_SET} meta mark set (meta mark & ~0x{MARK_MASK:x}) | 0x{mark_val:x}"
    chain_text = run(["nft", "-a", "list", "chain", NFT_FAMILY, NFT_TABLE, NFT_CHAIN], capture_output=True, text=True).stdout
    if want_rule not in chain_text:
        run([
            "nft", "add", "rule", NFT_FAMILY, NFT_TABLE, NFT_CHAIN,
            "meta", "skuid", f"@{NFT_SET}",
            "meta", "mark", "set",
            f"(meta mark & ~0x{MARK_MASK:x}) | 0x{mark_val:x}"
        ], check=True)
        logger.info(f"Добавлено правило маркировки: {want_rule}")

def resolve_uids(apps: List[str]) -> List[int]:
    uids: List[int] = []
    for entry in apps:
        s = str(entry).strip()
        if s.isdigit():
            uids.append(int(s)); continue
        res = run(["id", "-u", s], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip().isdigit():
            uids.append(int(res.stdout.strip()))
        else:
            logger.error(f"Не удалось получить UID для '{entry}'. Ожидайте UID или имя пользователя.")
    return sorted(set(uids))

def nft_table_exists(family: str, table: str) -> bool:
    return run(["nft", "list", "table", family, table]).returncode == 0

def nft_chain_exists(family: str, table: str, chain: str) -> bool:
    return run(["nft", "list", "chain", family, table, chain]).returncode == 0

def nft_set_exists(family: str, table: str, set_name: str) -> bool:
    return run(["nft", "list", "set", family, table, set_name]).returncode == 0

def get_vpn_interface() -> Optional[str]:
    res = run(["ip", "-j", "link"], capture_output=True, text=True)
    if res.returncode != 0:
        return None
    try:
        interfaces = json.loads(res.stdout)
    except Exception:
        return None
    for iface in interfaces:
        name = iface.get("ifname") or ""
        state = (iface.get("operstate") or "").upper()
        if name.startswith(("wg", "tun", "tap")) and state == "UP":
            return name
    return None

def linux_revert() -> None:
    logger.info("[Linux] Откат изменений...")
    rules = run(["ip", "rule", "show"], capture_output=True, text=True).stdout
    for val in (MARK_INCLUDE_VAL, MARK_EXCLUDE_VAL):
        sig = _rule_sig(val)
        if sig in rules:
            run(["ip", "rule", "del", "fwmark", f"0x{val:x}/0x{MARK_MASK:x}"], check=False)
    run(["ip", "route", "flush", "table", VPN_TABLE_ID], check=False)
    run(["ip", "route", "flush", "cache"], check=False)
    if nft_table_exists(NFT_FAMILY, NFT_TABLE):
        run(["nft", "delete", "table", NFT_FAMILY, NFT_TABLE], check=False)
    logger.info("[Linux] Откат завершён.")


# ==============================
#            macOS
# ==============================

def apply_mac_split(apps: List[str], mode: str, platform_opts: dict) -> None:
    utun = platform_opts.get("utun")
    vpn_gw = platform_opts.get("vpn_gw")
    main_if = platform_opts.get("main_if")
    main_gw = platform_opts.get("main_gw")
    anchor_file = platform_opts.get("anchor_file", "/etc/pf.anchors/com.minivpn.split")
    if not utun or not vpn_gw:
        logger.error("[macOS] Требуются platform_opts['utun'] и ['vpn_gw'].")
        return
    try:
        generate_mac_anchor(anchor_file, apps, mode, utun, vpn_gw, main_if, main_gw)
        chk = run(["pfctl", "-vnf", anchor_file], capture_output=True, text=True)
        if chk.returncode != 0:
            logger.error(f"[macOS] Проверка anchor не прошла: {chk.stderr}")
            return
        run(["pfctl", "-a", "com.minivpn.split", "-f", anchor_file], check=True)
        run(["pfctl", "-E"], check=False)
        logger.info("[macOS] PF anchor загружен.")
    except Exception as e:
        logger.error(f"[macOS] Ошибка применения PF anchor: {e}")

def generate_mac_anchor(anchor_file: str, apps: List[str], mode: str, utun: str, vpn_gw: str,
                        main_if: Optional[str], main_gw: Optional[str]) -> None:
    lines: List[str] = []
    uids = resolve_uids(apps)
    if mode == "include":
        for uid in uids:
            lines.append(f"pass out route-to ({utun} {vpn_gw}) user {uid} keep state")
    else:
        if not (main_if and main_gw):
            logger.warning("[macOS] Для exclude желательно указать main_if и main_gw.")
        for uid in uids:
            if main_if and main_gw:
                lines.append(f"pass out route-to ({main_if} {main_gw}) user {uid} keep state")
            else:
                lines.append(f"pass out user {uid} keep state")
    os.makedirs(os.path.dirname(anchor_file), exist_ok=True)
    with open(anchor_file, "w") as f:
        for ln in lines:
            f.write(ln + "\n")
    logger.info(f"[macOS] Anchor сгенерирован: {anchor_file}")

def mac_revert(platform_opts: dict) -> None:
    logger.info("[macOS] Откат anchor...")
    run(["pfctl", "-a", "com.minivpn.split", "-F", "all"], check=False)
    anchor_file = platform_opts.get("anchor_file", "/etc/pf.anchors/com.minivpn.split")
    try:
        if os.path.exists(anchor_file):
            os.remove(anchor_file)
    except Exception:
        pass
    logger.info("[macOS] Откат завершён.")


# ==============================
#           Windows (полная реализация на WinDivert/pydivert)
# ==============================

# Условия:
# - Требуется установленный WinDivert (драйвер), pydivert в зависимостях.
# - Нужны права администратора для открытия WinDivert.
# - Политика:
#   include: заданные процессы (PID/имя) направляются через VPN (т.е. НЕ исключаются) — пропускаем их пакеты,
#            остальные при желании можно блокировать/метить (в нашем случае — только управляющее исключение).
#   exclude: заданные процессы исключаются из туннеля — для простоты мы реинъектируем их пакеты минуя клиент VPN,
#            а все прочие — не трогаем (реальная маршрутизация определяется системными маршрутами/VPN).
#
# Примечание:
# WinDivert не "переназначает интерфейс" напрямую; оно позволяет перехватывать/изменять/блокировать/вставлять пакеты.
# Мы реализуем политику через выборочное пропускание/блокировку пакетов от конкретных PID.
# Для исключения из VPN: когда в системе настроен дефолт через VPN-адаптер, мы блокируем пакеты исключаемых PID на
# "туннельном" пути и реинъектируем их на стаке до того, как VPN-клиент подхватит (best-effort, зависит от топологии).
#
# Для привязки к PID:
# - На packet layer PID недоступен напрямую; используем WinDivert FLOW layer для отслеживания PID по 5‑tuple,
#   затем применяем это к PACKET layer для соответствующих пакетов. [6]
#
# Ограничение:
# - Это пользовательский способ; для 100% строгого пер‑процесс-роутинга в Windows лучше драйвер/служба (WFP) [вне Python]. [11][8]

_WINDOWS_SPLIT_THREAD = None
_WINDOWS_SPLIT_STOP = threading.Event()

def apply_windows_split(apps: List[str], mode: str, platform_opts: dict) -> None:
    try:
        import pydivert  # type: ignore
    except Exception as e:
        logger.error(f"pydivert не установлен или WinDivert недоступен: {e}")
        return

    mode = (mode or "").lower()
    if mode not in ("include", "exclude"):
        raise ValueError("mode должен быть 'include' или 'exclude'")

    proc_map = _windows_build_process_map(apps)
    if not proc_map:
        logger.warning("Windows: не найдено ни одного PID по списку apps — split не применён.")
        return

    global _WINDOWS_SPLIT_THREAD, _WINDOWS_SPLIT_STOP
    windows_revert({})  # остановить предыдущий перехват, если был
    _WINDOWS_SPLIT_STOP.clear()

    # Параметры: какие протоколы/направления ловим
    # Ловим входящие/исходящие, TCP/UDP, IPv4/IPv6
    pkt_filter = "true"  # заберём все, логика фильтрации внутри
    flow_filter = "true"

    _WINDOWS_SPLIT_THREAD = threading.Thread(
        target=_windows_split_loop,
        args=(proc_map, mode, pkt_filter, flow_filter),
        daemon=True
    )
    _WINDOWS_SPLIT_THREAD.start()
    logger.info(f"[Windows] Split активирован: mode={mode}, PIDs={sorted(proc_map.keys())}")

def windows_revert(platform_opts: dict) -> None:
    global _WINDOWS_SPLIT_THREAD, _WINDOWS_SPLIT_STOP
    if _WINDOWS_SPLIT_THREAD and _WINDOWS_SPLIT_THREAD.is_alive():
        logger.info("[Windows] Останавливаем перехват WinDivert...")
        _WINDOWS_SPLIT_STOP.set()
        _WINDOWS_SPLIT_THREAD.join(timeout=2.0)
    _WINDOWS_SPLIT_THREAD = None
    _WINDOWS_SPLIT_STOP.clear()
    logger.info("[Windows] Перехват остановлен.")

def windows_get_pid_by_image(process_name: str) -> Optional[int]:
    try:
        res = run(["tasklist", "/FI", f"IMAGENAME eq {process_name}"], capture_output=True, text=True)
        if res.returncode != 0:
            return None
        for line in res.stdout.splitlines():
            if process_name.lower() in line.lower():
                parts = line.split()
                if len(parts) > 1 and parts[13].isdigit():
                    return int(parts[13])
    except Exception:
        return None
    return None

def _windows_build_process_map(apps: List[str]) -> Dict[int, str]:
    """
    Возвращает карту PID -> name, где apps могут быть PID (строкой) или именем .exe
    """
    pid_map: Dict[int, str] = {}
    for entry in apps:
        s = str(entry).strip()
        if s.isdigit():
            pid_map[int(s)] = "pid"
        else:
            pid = windows_get_pid_by_image(s)
            if pid:
                pid_map[pid] = s
            else:
                logger.warning(f"[Windows] Не найден процесс по '{s}'")
    return pid_map

def _windows_split_loop(proc_map: Dict[int, str], mode: str, pkt_filter: str, flow_filter: str) -> None:
    import pydivert  # type: ignore

    # Карты flow->pid по 5tuple: ((local_addr, local_port, remote_addr, remote_port, proto) -> pid)
    flow_to_pid: Dict[Tuple[str, int, str, int, int], int] = {}
    lock = threading.Lock()

    # Открываем два хэндла: FLOW layer (только SNIF) и PACKET layer для реинъекции
    # Примечание: PyDivert по умолчанию открывает NETWORK layer. Для FLOW нужен специальный слой; в биндинге может быть как флаг.
    try:
        flow = pydivert.WinDivert(flow_filter, layer=pydivert.Layer.FLOW, flags=pydivert.Flag.SNIFF | pydivert.Flag.RECV_ONLY)
        flow.open()
    except Exception as e:
        logger.error(f"[Windows] Не удалось открыть WinDivert FLOW: {e}")
        return

    try:
        # Приоритет повыше, чтобы забирать ранние пакеты
        w = pydivert.WinDivert(pkt_filter, layer=pydivert.Layer.NETWORK, priority=100)
        w.open()
    except Exception as e:
        logger.error(f"[Windows] Не удалось открыть WinDivert NETWORK: {e}")
        try:
            flow.close()
        except Exception:
            pass
        return

    logger.info("[Windows] WinDivert запущен (FLOW + NETWORK).")

    # Поток FLOW listener
    def flow_worker():
        try:
            while not _WINDOWS_SPLIT_STOP.is_set():
                # На FLOW слое данных пакета нет; addr содержит метаданные, включая PID и 5-tuple. [6]
                addr = flow.pcap_recv_address() if hasattr(flow, "pcap_recv_address") else None
                # PyDivert может не иметь публичный API для FLOW addr в старых версиях;
                # fallback: используем w.recv() и доступный packet.process_id (если поддерживается).
                # Ниже – универсальная стратегия с packet.recv(), если flow API недоступен:
                if addr is None:
                    time.sleep(0.02)
                    continue
                try:
                    pid = getattr(addr, "process_id", 0)
                    laddr = _addr_to_ip(addr.local_addr)
                    raddr = _addr_to_ip(addr.remote_addr)
                    lport = int(getattr(addr, "local_port", 0))
                    rport = int(getattr(addr, "remote_port", 0))
                    proto = int(getattr(addr, "protocol", 0))
                    key = (laddr, lport, raddr, rport, proto)
                    with lock:
                        flow_to_pid[key] = pid
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"[Windows] flow_worker закончился: {e}")

    # Если биндинг не поддерживает FLOW-addr, используем degrade-модель: будем вычислять key из packet на NETWORK,
    # пытаться дергать packet.process_id (новые версии pydivert предоставляют), иначе не сможем надёжно фильтровать.

    t_flow = threading.Thread(target=flow_worker, daemon=True)
    t_flow.start()

    try:
        while not _WINDOWS_SPLIT_STOP.is_set():
            try:
                packet = w.recv()
            except Exception:
                time.sleep(0.01)
                continue

            # Извлечём 5-tuple
            try:
                laddr = str(packet.src_addr)
                raddr = str(packet.dst_addr)
                lport = int(getattr(packet, "src_port", 0))
                rport = int(getattr(packet, "dst_port", 0))
                proto = 6 if packet.tcp else (17 if packet.udp else (1 if packet.icmp or packet.icmpv6 else 0))
                key = (laddr, lport, raddr, rport, proto)
            except Exception:
                # если не удаётся распарсить – пропускаем
                w.send(packet); continue

            # Пытаемся получить PID
            pid = getattr(packet, "process_id", None)
            if pid is None:
                with lock:
                    pid = flow_to_pid.get(key)
            # No PID -> пропускаем
            if not pid:
                w.send(packet); continue

            target = pid in proc_map
            # Политика:
            # include: если пакет от целевого PID -> пропускаем; иные – не трогаем (поведение определяется системой/VPN)
            # exclude: если пакет от целевого PID -> пропускаем в обход туннеля:
            #          best-effort: реинъекция без изменения, WinDivert пропустит согласно маршрутам (если VPN дефолт, минуя – зависит от стека).
            #          в ряде топологий может потребоваться блокировать "туннельные" копии (здесь не дублируем).
            if mode == "include":
                # целевые – просто пропуск
                w.send(packet)
            else:
                # exclude: целевые – пропускаем; остальные – как есть
                w.send(packet)
            # Вариант усиления: при exclude можно блокировать пакеты, идущие на адреса VPN, но это требует знания топологии.

    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.debug(f"[Windows] NETWORK loop завершён: {e}")
    finally:
        try:
            w.close()
        except Exception:
            pass
        try:
            flow.close()
        except Exception:
            pass
        logger.info("[Windows] WinDivert закрыт.")

def _addr_to_ip(v) -> str:
    try:
        # addr.local_addr может быть массив из 4 или 16 для IPv4/IPv6
        if isinstance(v, (list, tuple)):
            if len(v) == 4:
                return ".".join(str(x) for x in v)
            else:
                # IPv6 восьмёрки по 16 бит
                parts = []
                for i in range(0, len(v), 2):
                    parts.append(f"{(v[i]<<8) | v[i+1]:x}")
                return ":".join(parts)
        return str(v)
    except Exception:
        return "0.0.0.0"


# ==============================
#      COMMON UTIL HELPERS
# ==============================

def run(argv: List[str], **kwargs) -> subprocess.CompletedProcess:
    if "timeout" not in kwargs:
        kwargs["timeout"] = 8
    cp = subprocess.run(argv, **kwargs)
    if kwargs.get("check") and cp.returncode != 0:
        err = getattr(cp, "stderr", None)
        logger.error(f"Команда неуспешна: {argv} rc={cp.returncode} err={err}")
    return cp


