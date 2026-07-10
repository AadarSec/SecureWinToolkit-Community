from .public_ip import run_scan as public_ip_scan
from .default_gateway import run_scan as default_gateway_scan
from .dns_servers import run_scan as dns_servers_scan
from .dhcp_status import run_scan as dhcp_status_scan
from .mac_address import run_scan as mac_address_scan
from .network_adapter import run_scan as network_adapter_scan
from .adapter_speed import run_scan as adapter_speed_scan
from .ipv6 import run_scan as ipv6_scan
from .mtu import run_scan as mtu_scan
from .network_profile import run_scan as network_profile_scan
from .llmnr import run_scan as llmnr_scan
from .netbios import run_scan as netbios_scan
from .dns_security import run_scan as dns_security_scan
from .firewall_network_policy import run_scan as firewall_network_policy_scan
from .wifi_encryption import run_scan as wifi_encryption_scan
from .ssid import run_scan as ssid_scan
from .signal_strength import run_scan as signal_strength_scan
from .listening_ports import run_scan as listening_ports_scan
from .established_connections import run_scan as established_connections_scan
from .running_network_services import run_scan as running_network_services_scan
from .remote_endpoints import run_scan as remote_endpoints_scan
from .connection_processes import run_scan as connection_processes_scan
from .active_listening_sockets import run_scan as active_listening_sockets_scan

SCANNER_MAP = {
    "Public IP Address": public_ip_scan,
    "Default Gateway": default_gateway_scan,
    "DNS Servers": dns_servers_scan,
    "DHCP Status": dhcp_status_scan,
    "MAC Address": mac_address_scan,
    "Active Network Adapter": network_adapter_scan,
    "Adapter Speed": adapter_speed_scan,
    "IPv6 Status": ipv6_scan,
    "MTU": mtu_scan,
    "Network Profile (Public / Private)": network_profile_scan,
    "LLMNR": llmnr_scan,
    "Firewall Network Policy": firewall_network_policy_scan,
    "NetBIOS": netbios_scan,
    "DNS Security": dns_security_scan,
    "Wi-Fi Encryption": wifi_encryption_scan,
    "SSID": ssid_scan,
    "Signal Strength": signal_strength_scan,
    "Listening Ports": listening_ports_scan,
    "Established Connections": established_connections_scan,
    "Running Network Services": running_network_services_scan,
    "Remote Endpoints": remote_endpoints_scan,
    "Connection Processes": connection_processes_scan,
    "Active Listening Sockets": active_listening_sockets_scan,
    
}