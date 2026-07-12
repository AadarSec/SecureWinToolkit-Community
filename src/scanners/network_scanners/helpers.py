"""
SecureWin Toolkit
Network Scanner Helpers

Shared helper functions used by all Network Audit scanners.

Optimization notes:
- run_powershell() centralizes the subprocess + JSON parsing boilerplate that
  was previously duplicated in dns_security, firewall_network_policy, llmnr,
  netbios and network_isolation.
- get_netstat_connections() centralizes the "run netstat -ano and parse TCP
  lines" logic that was previously duplicated in active_listening_sockets,
  connection_processes, established_connections and listening_ports.
- get_process_name_map() replaces the old pattern of shelling out to
  `tasklist` once PER PID (very slow on machines with many connections/
  sockets) with a single `tasklist` call that resolves every PID at once.
  It also parses the CSV output with the csv module instead of a naive
  str.split(","), which previously could break on fields containing commas
  (e.g. memory usage like "12,345 K").
- build_error_result() centralizes the repeated "Warning / Low / Unable to
  retrieve ..." error dict that was copy-pasted across nearly every scanner.
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
import urllib.request


# ---------------------------------------------------------------------------
# PowerShell execution
# ---------------------------------------------------------------------------

def run_powershell(script: str, timeout: int = 10):
    """
    Runs a PowerShell script and returns the parsed JSON output.

    Raises RuntimeError / json.JSONDecodeError on failure so callers can
    handle it with a single try/except, instead of re-implementing the
    subprocess + return-code + empty-output checks every time.
    """

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell command failed.")

    output = result.stdout.strip()

    if not output:
        raise RuntimeError("PowerShell returned no output.")

    return json.loads(output)


# ---------------------------------------------------------------------------
# Active network adapter info
# ---------------------------------------------------------------------------

def get_active_network_info():
    """
    Returns information for the currently active network adapter.

    Returns:
        dict | None
    """

    powershell = r"""
$candidates = Get-NetIPConfiguration | Where-Object {
    $_.NetAdapter.Status -eq 'Up' -and
    $_.IPv4Address
}

if (-not $candidates)
{
    exit
}

# Prefer adapter with Internet connectivity.
$adapter = $candidates | Where-Object {
    $_.NetProfile.IPv4Connectivity -eq 'Internet'
} | Select-Object -First 1

# Fallback: adapter with gateway.
if ($null -eq $adapter)
{
    $adapter = $candidates | Where-Object {
        $_.IPv4DefaultGateway
    } | Select-Object -First 1
}

# Last fallback.
if ($null -eq $adapter)
{
    $adapter = $candidates | Select-Object -First 1
}

$ipInterface = Get-NetIPInterface `
    -InterfaceIndex $adapter.InterfaceIndex `
    -AddressFamily IPv4

$netAdapter = Get-NetAdapter `
    -InterfaceIndex $adapter.InterfaceIndex

$mtuInfo = Get-NetIPInterface `
    -InterfaceIndex $adapter.InterfaceIndex `
    -AddressFamily IPv4

$dhcpStatus = $ipInterface.Dhcp.ToString()

$networkCategory = switch ($adapter.NetProfile.NetworkCategory)
{
    0 { "Public" }
    1 { "Private" }
    2 { "Domain" }
    Default { "Unknown" }
}

$result = @{
    InterfaceAlias = $adapter.InterfaceAlias
    InterfaceDescription = $adapter.InterfaceDescription
    IPv4 = $adapter.IPv4Address.IPAddress
    IPv6 = if ($adapter.IPv6Address) { $adapter.IPv6Address.IPAddress } else { $null }
    Gateway = if ($adapter.IPv4DefaultGateway) { $adapter.IPv4DefaultGateway.NextHop } else { $null }
    DNSServers = $adapter.DNSServer.ServerAddresses
    DHCP = $dhcpStatus
    NetworkCategory = $networkCategory
    MACAddress = $adapter.NetAdapter.MacAddress
    LinkSpeed = $netAdapter.LinkSpeed
    MediaType = $netAdapter.MediaType
    Status = $netAdapter.Status
    MTU = $mtuInfo.NlMtu

}

$result | ConvertTo-Json -Depth 4
"""

    try:
        return run_powershell(powershell, timeout=10)
    except Exception:
        return None


def get_public_ip():
    """
    Returns the system's public IPv4 address.

    Queries multiple providers and returns the most common
    valid IPv4 address.
    """

    import ipaddress
    from collections import Counter

    providers = [
        ("ipify", "https://api.ipify.org?format=json"),
        ("icanhazip", "https://ipv4.icanhazip.com"),
        ("aws", "https://checkip.amazonaws.com"),
        ("ifconfig", "https://ifconfig.me/ip"),
    ]

    results = []

    for name, url in providers:

        try:

            with urllib.request.urlopen(url, timeout=5) as response:

                raw = response.read().decode("utf-8").strip()

            if not raw:
                continue

            if raw.startswith("{"):

                data = json.loads(raw)

                ip = (
                    data.get("ip")
                    or data.get("ip_addr")
                    or ""
                ).strip()

            else:

                ip = raw

            try:

                ipaddress.ip_address(ip)

                results.append(ip)

            except ValueError:

                continue

        except Exception:

            continue

    if not results:
        return None

    counter = Counter(results)

    return counter.most_common(1)[0][0]


# ---------------------------------------------------------------------------
# netstat / process helpers (shared by the connection & port scanners)
# ---------------------------------------------------------------------------

def get_netstat_connections(timeout: int = 15):
    """
    Runs `netstat -ano` once and returns a list of parsed TCP connection
    dicts: {"local": ..., "remote": ..., "state": ..., "pid": ...}.

    Centralizing this means the LISTENING / ESTABLISHED scanners no longer
    each re-run netstat and re-implement the same line-splitting logic.
    """

    result = subprocess.run(
        ["netstat", "-ano"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    connections = []

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line.startswith("TCP"):
            continue

        parts = line.split()

        if len(parts) < 5:
            continue

        connections.append({
            "local": parts[1],
            "remote": parts[2],
            "state": parts[3],
            "pid": parts[4],
        })

    return connections


def get_process_name_map(timeout: int = 10) -> dict:
    """
    Runs `tasklist` ONCE and returns a {pid: process_name} map for every
    running process.

    This replaces the previous pattern of calling `tasklist /FI "PID eq X"`
    separately for every single connection/socket found, which meant a
    system with, say, 80 open sockets triggered 80 extra subprocess calls.
    With this helper it's always exactly 1 call, no matter how many PIDs
    need to be resolved.

    Uses csv.reader instead of a naive str.split(",") so that fields
    containing commas (e.g. "12,345 K" memory usage) don't corrupt the
    parsed name/PID columns.
    """

    mapping: dict = {}

    try:

        result = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        reader = csv.reader(io.StringIO(result.stdout))

        for row in reader:

            if len(row) < 2:
                continue

            name, pid = row[0], row[1]

            mapping[pid] = name

    except Exception:

        pass

    return mapping


# ---------------------------------------------------------------------------
# Wi-Fi interface helper (shared by SSID, Signal Strength, Wi-Fi Encryption)
# ---------------------------------------------------------------------------

def get_wlan_interface_info(timeout: int = 10):
    """
    Runs `netsh wlan show interfaces` ONCE and parses the "Key : Value"
    style output into a dict.

    Returns None if no wireless adapter is currently connected.

    Previously the SSID, Signal Strength, and Wi-Fi Encryption scanners
    each ran this exact same command and re-implemented the exact same
    line-splitting logic independently. Centralizing it here means the
    parsing only exists in one place.
    """

    result = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    output = result.stdout

    if "State" not in output:
        return None

    info: dict = {}

    for line in output.splitlines():

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        info[key.strip()] = value.strip()

    return info


# ---------------------------------------------------------------------------
# Shared error result builder
# ---------------------------------------------------------------------------

def build_error_result(error, recommendation: str, detection_method: str) -> dict:
    """
    Builds the standard "something went wrong" result dict.

    Nearly every scanner ended with an identical
    except Exception as e: return {"status": "Warning", "risk": "Low", ...}
    block. This collapses that repetition to a single call.
    """

    return {
        "status": "Warning",
        "risk": "Low",
        "details": str(error),
        "recommendation": recommendation,
        "detection_method": detection_method,
        "confidence": "Low",
        "data": {},
    }
