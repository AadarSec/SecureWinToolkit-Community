import psutil
import time

_last_disk = psutil.disk_io_counters()
_last_time = time.time()


def get_cpu_usage():
    return psutil.cpu_percent(interval=0.1)


def get_ram_usage():
    return psutil.virtual_memory().percent


def get_disk_usage():
    return psutil.disk_usage("C:\\").percent


def get_disk_activity():
    global _last_disk, _last_time

    current = psutil.disk_io_counters()
    now = time.time()

    bytes_changed = (
        (current.read_bytes - _last_disk.read_bytes)
        + (current.write_bytes - _last_disk.write_bytes)
    )

    elapsed = max(now - _last_time, 0.1)
    mb_per_sec = (bytes_changed / 1024 / 1024) / elapsed

    _last_disk = current
    _last_time = now

    # Dashboard scale (0-100)
    return min(round(mb_per_sec * 10), 100)
