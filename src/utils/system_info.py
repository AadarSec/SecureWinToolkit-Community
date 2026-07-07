import getpass
import platform
import re
import socket
import time
import psutil
import winreg

_CV_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def _read_reg(name, default="Unknown", path=_CV_PATH, hive=winreg.HKEY_LOCAL_MACHINE):
    try:
        key = winreg.OpenKey(hive, path)
        value, _ = winreg.QueryValueEx(key, name)
        return str(value)
    except Exception:
        return default


def _get_build_number():
    try:
        return int(_read_reg("CurrentBuild", "0"))
    except ValueError:
        return 0


def get_windows_edition():
    build = _get_build_number()
    edition = _read_reg("ProductName", platform.system())

    if edition and build >= 22000 and "Windows 10" in edition:
        edition = edition.replace("Windows 10", "Windows 11")

    return edition


def get_windows_version():
    return _read_reg("DisplayVersion", platform.version())


def get_windows_build():
    build = _read_reg("CurrentBuild", "")
    ubr = _read_reg("UBR", "")
    return f"{build}.{ubr}" if build else platform.version()


def get_processor_name():
    """
    Returns a cleaned-up CPU name, e.g.:
    "13th Gen Intel(R) Core(TM) i5-1335U" -> "13th Gen Intel Core i5-1335U"
    """
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        )
        name = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
    except Exception:
        name = platform.processor()

    if name:
        name = name.replace("(R)", "").replace("(TM)", "")
        name = re.sub(r"\s{2,}", " ", name).strip()

    return name


def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"


def get_network_adapter():
    """
    Returns a friendly adapter description, e.g. "Wi-Fi" or "Ethernet".
    Matches the outbound IP to its interface name via psutil, so it
    reflects whichever adapter is actually carrying traffic.
    """
    ip = get_ip_address()
    if ip == "Unknown":
        return "Unknown"

    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        for iface_name, iface_addrs in addrs.items():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET and addr.address == ip:
                    is_up = stats.get(iface_name).isup if iface_name in stats else False
                    lname = iface_name.lower()

                    if "wi-fi" in lname or "wifi" in lname or "wlan" in lname:
                        kind = "Wi-Fi"
                    elif "ethernet" in lname or "eth" in lname:
                        kind = "Ethernet"
                    else:
                        kind = iface_name

                    return kind if is_up else f"{kind} (inactive)"

        return "Unknown"
    except Exception:
        return "Unknown"


def get_uptime():
    up = int(time.time()) - int(psutil.boot_time())
    return f"{up // 86400}d {(up % 86400) // 3600}h"


def get_last_update():
    last_time = _read_reg(
        "LastSuccessTime",
        default=None,
        path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install",
    )
    if last_time:
        return last_time

    install_date = _read_reg("InstallDate", default=None)
    if install_date:
        try:
            ts = int(install_date)
            return time.strftime("%Y-%m-%d", time.localtime(ts))
        except ValueError:
            pass

    return "Unknown"


def get_disk_details(drive="C:\\"):
    """
    Returns (percent_used, used_gb, total_gb) for the given drive.
    """
    usage = psutil.disk_usage(drive)
    used_gb = round(usage.used / (1024 ** 3))
    total_gb = round(usage.total / (1024 ** 3))
    return usage.percent, used_gb, total_gb


def get_system_info():
    vm = psutil.virtual_memory()
    disk_percent, disk_used_gb, disk_total_gb = get_disk_details()

    return {
        "Computer Name": socket.gethostname(),
        "Current User": getpass.getuser(),
        "Windows Edition": get_windows_edition(),
        "Windows Version": get_windows_version(),
        "Windows Build": get_windows_build(),
        "Processor": get_processor_name(),
        "IP Address": get_ip_address(),
        "Network Adapter": get_network_adapter(),
        "RAM Installed": f"{round(vm.total / (1024 ** 3))} GB",
        "Disk Usage": disk_percent,
        "Disk Used GB": disk_used_gb,
        "Disk Total GB": disk_total_gb,
        "Uptime": get_uptime(),
        "Last Update": get_last_update(),
    }


if __name__ == "__main__":
    t0 = time.perf_counter()
    info = get_system_info()
    elapsed = time.perf_counter() - t0

    for k, v in info.items():
        print(f"{k}: {v}")
    print(f"\n(gathered in {elapsed*1000:.1f} ms)")
