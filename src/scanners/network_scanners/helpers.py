"""
SecureWin Toolkit
Network Scanner Helpers

Shared helper functions used by all Network Audit scanners.
"""

from __future__ import annotations

import json
import subprocess
import urllib.request


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

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                powershell,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return None

        output = result.stdout.strip()

        if not output:
            return None

        return json.loads(output)

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