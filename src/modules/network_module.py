"""
Network Module for Offensive Security Operations
Provides network scanning and reconnaissance capabilities using scapy
"""

import logging
import socket
import time
from typing import Dict, Any, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, sr1, sr
from scapy.layers.inet import ICMP
from scapy.packet import Packet

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Common ports to scan
COMMON_PORTS = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    80,   # HTTP
    110,  # POP3
    143,  # IMAP
    443,  # HTTPS
    993,  # IMAPS
    995,  # POP3S
    1433, # MSSQL
    1521, # Oracle
    3306, # MySQL
    3389, # RDP
    5432, # PostgreSQL
    5900, # VNC
    8080, # HTTP-Alt
    8443  # HTTPS-Alt
]

# Service banners for common ports
SERVICE_BANNERS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether, ARP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress Scapy warnings
conf.verb = 0


@dataclass
class PortScanResult:
    """Result of a port scan."""
    port: int
    is_open: bool
    service: Optional[str]
    banner: Optional[str]
    response_time: float


@dataclass
class NetworkScanResult:
    """Comprehensive network scan result."""
    target: str
    timestamp: str
    is_alive: bool
    ping_response_time: Optional[float]
    open_ports: List[PortScanResult]
    os_fingerprint: Optional[str]
    mac_address: Optional[str]
    hostnames: List[str]
    error_messages: List[str]


class NetworkScanner:
    """
    Network scanner using Scapy for various reconnaissance tasks.
    """
    
    def __init__(self, timeout: float = 3.0, max_threads: int = 50):
        """
        Initialize the network scanner.
        
        Args:
            timeout: Timeout for network operations in seconds
            max_threads: Maximum number of threads for concurrent scanning
        """
        self.timeout = timeout
        self.max_threads = max_threads
        
        # Common ports to scan
        self.common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        
        # Port scan techniques
        self.scan_techniques = ['syn_scan', 'connect_scan', 'udp_scan']
    
    def _is_valid_ip(self, target: str) -> bool:
        """Check if target is a valid IP address."""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _resolve_hostname(self, target: str) -> List[str]:
        """Resolve hostname to IP addresses."""
        try:
            return socket.gethostbyname_ex(target)[2]
        except socket.gaierror:
            return []
    
    def ping_host(self, target: str) -> Tuple[bool, Optional[float]]:
        """
        Ping a host to check if it's alive.
        
        Args:
            target: IP address or hostname
            
        Returns:
            Tuple of (is_alive, response_time)
        """
        try:
            # Resolve hostname if needed
            if not self._is_valid_ip(target):
                ips = self._resolve_hostname(target)
                if not ips:
                    return False, None
                target = ips[0]
            
            # Send ICMP echo request
            start_time = time.time()
            packet = IP(dst=target)/ICMP()
            reply = sr1(packet, timeout=self.timeout, verbose=0)
            
            if reply is not None:
                response_time = (time.time() - start_time) * 1000  # Convert to ms
                return True, response_time
            else:
                return False, None
                
        except Exception as e:
            logger.error(f"Ping failed for {target}: {e}")
            return False, None
    
    def _syn_scan_port(self, target: str, port: int) -> PortScanResult:
        """
        Perform SYN scan on a specific port.
        
        Args:
            target: Target IP address
            port: Port to scan
            
        Returns:
            PortScanResult
        """
        start_time = time.time()
        
        try:
            # Send SYN packet
            packet = IP(dst=target)/TCP(dport=port, flags='S')
            reply = sr1(packet, timeout=self.timeout, verbose=0)
            
            response_time = (time.time() - start_time) * 1000
            
            if reply is None:
                return PortScanResult(port, False, None, None, response_time)
            
            if reply.haslayer(TCP):
                tcp_layer = reply.getlayer(TCP)
                
                if tcp_layer.flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst_packet = IP(dst=target)/TCP(dport=port, flags='R')
                    send(rst_packet, verbose=0)
                    
                    service = self.common_ports.get(port, f'Unknown-{port}')
                    banner = self._grab_banner(target, port)
                    
                    return PortScanResult(port, True, service, banner, response_time)
                elif tcp_layer.flags == 0x14:  # RST
                    return PortScanResult(port, False, None, None, response_time)
            
            return PortScanResult(port, False, None, None, response_time)
            
        except Exception as e:
            logger.error(f"SYN scan failed for {target}:{port} - {e}")
            return PortScanResult(port, False, None, None, 0)
    
    def _connect_scan_port(self, target: str, port: int) -> PortScanResult:
        """
        Perform TCP connect scan on a specific port.
        
        Args:
            target: Target IP address
            port: Port to scan
            
        Returns:
            PortScanResult
        """
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((target, port))
            response_time = (time.time() - start_time) * 1000
            
            if result == 0:
                service = self.common_ports.get(port, f'Unknown-{port}')
                banner = self._grab_banner(target, port)
                sock.close()
                return PortScanResult(port, True, service, banner, response_time)
            else:
                sock.close()
                return PortScanResult(port, False, None, None, response_time)
                
        except Exception as e:
            logger.error(f"Connect scan failed for {target}:{port} - {e}")
            return PortScanResult(port, False, None, None, 0)
    
    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """
        Grab service banner from an open port.
        
        Args:
            target: Target IP address
            port: Port to grab banner from
            
        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            sock.connect((target, port))
            
            # Send a simple HTTP request for web servers
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port in [443, 8443]:
                # For HTTPS, we'll just try to read the SSL/TLS handshake
                pass
            else:
                # For other services, try to read initial response
                pass
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                # Clean up the banner
                lines = banner.split('\n')
                if lines:
                    first_line = lines[0]
                    if len(first_line) > 100:
                        first_line = first_line[:100] + '...'
                    return first_line
            
            return None
            
        except Exception as e:
            logger.debug(f"Banner grab failed for {target}:{port} - {e}")
            return None
    
    def scan_ports(self, target: str, ports: List[int] = None, technique: str = 'syn_scan') -> List[PortScanResult]:
        """
        Scan multiple ports on a target.
        
        Args:
            target: Target IP address
            ports: List of ports to scan (default: common ports)
            technique: Scan technique ('syn_scan', 'connect_scan')
            
        Returns:
            List of PortScanResult objects
        """
        if ports is None:
            ports = list(self.common_ports.keys())
        
        results = []
        
        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(ports))) as executor:
            future_to_port = {}
            
            for port in ports:
                if technique == 'syn_scan':
                    future = executor.submit(self._syn_scan_port, target, port)
                else:
                    future = executor.submit(self._connect_scan_port, target, port)
                
                future_to_port[future] = port
            
            for future in as_completed(future_to_port):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.is_open:
                        logger.info(f"Port {result.port} is open on {target}")
                        
                except Exception as e:
                    port = future_to_port[future]
                    logger.error(f"Port scan error for {target}:{port} - {e}")
        
        return results
    
    def get_mac_address(self, target: str) -> Optional[str]:
        """
        Get MAC address of a target on local network.
        
        Args:
            target: Target IP address
            
        Returns:
            MAC address string or None
        """
        try:
            # Send ARP request
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target)
            arp_response = srp(arp_request, timeout=self.timeout, verbose=0)[0]
            
            if arp_response:
                return arp_response[0][1].hwsrc
            
        except Exception as e:
            logger.debug(f"MAC address lookup failed for {target}: {e}")
        
        return None
    
    def os_fingerprint(self, target: str) -> Optional[str]:
        """
        Basic OS fingerprinting using TTL and window size.
        
        Args:
            target: Target IP address
            
        Returns:
            OS guess string or None
        """
        try:
            # Send TCP packet to port 80 (commonly open)
            packet = IP(dst=target)/TCP(dport=80, flags='S')
            reply = sr1(packet, timeout=self.timeout, verbose=0)
            
            if reply and reply.haslayer(IP):
                ip_layer = reply.getlayer(IP)
                ttl = ip_layer.ttl
                
                # Basic TTL-based OS detection
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Cisco/Network Device"
                else:
                    return "Unknown"
                    
        except Exception as e:
            logger.debug(f"OS fingerprinting failed for {target}: {e}")
        
        return None
    
    def network_scan(self, target_ip: str) -> Dict[str, Any]:
        """
        Perform comprehensive network scan.
        
        Args:
            target_ip: Target IP address or hostname
            
        Returns:
            Dictionary with scan results
        """
        from datetime import datetime
        
        logger.info(f"Starting network scan for: {target_ip}")
        
        result = NetworkScanResult(
            target=target_ip,
            timestamp=datetime.now().isoformat(),
            is_alive=False,
            ping_response_time=None,
            open_ports=[],
            os_fingerprint=None,
            mac_address=None,
            hostnames=[],
            error_messages=[]
        )
        
        try:
            # Resolve hostname if needed
            if not self._is_valid_ip(target_ip):
                ips = self._resolve_hostname(target_ip)
                if not ips:
                    result.error_messages.append(f"Hostname resolution failed for {target_ip}")
                    return self._format_result(result, "failed")
                
                result.hostnames = [target_ip]
                target_ip = ips[0]
                result.target = target_ip
            
            # 1. Ping host to check if alive
            logger.info(f"Pinging {target_ip}...")
            is_alive, ping_time = self.ping_host(target_ip)
            result.is_alive = is_alive
            result.ping_response_time = ping_time
            
            if not is_alive:
                logger.warning(f"Host {target_ip} appears to be down")
                return self._format_result(result, "completed")
            
            # 2. Get MAC address (if on local network)
            logger.info("Getting MAC address...")
            result.mac_address = self.get_mac_address(target_ip)
            
            # 3. OS fingerprinting
            logger.info("Performing OS fingerprinting...")
            result.os_fingerprint = self.os_fingerprint(target_ip)
            
            # 4. Port scanning
            logger.info("Scanning common ports...")
            result.open_ports = self.scan_ports(target_ip)
            
            # Filter only open ports for summary
            open_ports = [p for p in result.open_ports if p.is_open]
            
            logger.info(f"Network scan completed for {target_ip}")
            logger.info(f"Found {len(open_ports)} open ports")
            
            return self._format_result(result, "completed")
            
        except Exception as e:
            error_msg = f"Network scan failed: {str(e)}"
            logger.error(error_msg)
            result.error_messages.append(error_msg)
            return self._format_result(result, "failed")
    
    def _format_result(self, result: NetworkScanResult, status: str) -> Dict[str, Any]:
        """Format the scan result for output."""
        open_ports = [p for p in result.open_ports if p.is_open]
        
        return {
            'target': result.target,
            'timestamp': result.timestamp,
            'status': status,
            'is_alive': result.is_alive,
            'ping_response_time_ms': result.ping_response_time,
            'summary': {
                'total_ports_scanned': len(result.open_ports),
                'open_ports_count': len(open_ports),
                'closed_ports_count': len(result.open_ports) - len(open_ports),
                'has_mac_address': bool(result.mac_address),
                'os_detected': bool(result.os_fingerprint)
            },
            'open_ports': [
                {
                    'port': p.port,
                    'service': p.service,
                    'banner': p.banner,
                    'response_time_ms': p.response_time
                }
                for p in open_ports
            ],
            'all_ports_scanned': [
                {
                    'port': p.port,
                    'is_open': p.is_open,
                    'service': p.service,
                    'response_time_ms': p.response_time
                }
                for p in result.open_ports
            ],
            'host_info': {
                'mac_address': result.mac_address,
                'os_fingerprint': result.os_fingerprint,
                'resolved_hostnames': result.hostnames
            },
            'error_messages': result.error_messages
        }


# Global network scanner instance
_network_scanner = None

def get_network_scanner() -> NetworkScanner:
    """Get or create the global network scanner instance."""
    global _network_scanner
    if _network_scanner is None:
        _network_scanner = NetworkScanner()
    return _network_scanner

def network_scan(target_ip: str, ports: List[int] = None, timeout: int = 3, max_threads: int = 50) -> Dict[str, Any]:
    """
    Perform TCP port scanning on target IP using scapy.
    
    Args:
        target_ip (str): Target IP address to scan
        ports (List[int], optional): List of ports to scan. Defaults to COMMON_PORTS
        timeout (int): Timeout for each port scan attempt in seconds
        max_threads (int): Maximum number of concurrent threads for scanning
        
    Returns:
        dict: Scan results with open ports and service information
    """
    try:
        # Validate target IP
        if not _is_valid_ip(target_ip):
            return {
                "success": False,
                "error": f"Invalid IP address: {target_ip}",
                "target_ip": target_ip,
                "open_ports": [],
                "service_info": {}
            }
        
        # Use default ports if none specified
        if ports is None:
            ports = COMMON_PORTS
        
        logger.info(f"Starting TCP port scan on {target_ip} for {len(ports)} ports")
        
        # Check if target is responsive
        if not _is_host_alive(target_ip):
            logger.warning(f"Target {target_ip} appears to be down or not responding")
            return {
                "success": True,
                "target_ip": target_ip,
                "open_ports": [],
                "service_info": {},
                "host_alive": False,
                "message": "Target host appears to be down"
            }
        
        # Perform port scan
        open_ports = []
        service_info = {}
        
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit scan tasks for each port
            future_to_port = {
                executor.submit(_scan_port, target_ip, port, timeout): port 
                for port in ports
            }
            
            # Collect results
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result["open"]:
                        open_ports.append(port)
                        service_info[port] = result["service_info"]
                        logger.info(f"Port {port} is OPEN on {target_ip} - {result['service_info']['service']}")
                except Exception as e:
                    logger.error(f"Error scanning port {port}: {e}")
        
        # Prepare results
        scan_results = {
            "success": True,
            "target_ip": target_ip,
            "open_ports": sorted(open_ports),
            "service_info": service_info,
            "host_alive": True,
            "total_ports_scanned": len(ports),
            "open_ports_count": len(open_ports),
            "scan_time": time.time()
        }
        
        logger.info(f"Scan completed for {target_ip}: {len(open_ports)} open ports found")
        return scan_results
        
    except Exception as e:
        logger.error(f"Network scan failed for {target_ip}: {e}")
        return {
            "success": False,
            "error": str(e),
            "target_ip": target_ip,
            "open_ports": [],
            "service_info": {}
        }


# Test function
if __name__ == "__main__":
    # Test the network scanner
    scanner = NetworkScanner()
    
    # Test with a common target
    test_targets = ["127.0.0.1", "8.8.8.8", "example.com"]
    
    for target in test_targets:
        print(f"\n=== Scanning {target} ===")
        result = scanner.network_scan(target)
        print(f"Status: {result['status']}")
        print(f"Is alive: {result['is_alive']}")
        print(f"Open ports: {result['summary']['open_ports_count']}")
        
        if result['open_ports']:
            for port in result['open_ports']:
                print(f"  Port {port['port']}/{port['service']}: {port['banner'] or 'No banner'}")
        
        if result['host_info']['os_fingerprint']:
            print(f"OS: {result['host_info']['os_fingerprint']}")
        
        if result['host_info']['mac_address']:
            print(f"MAC: {result['host_info']['mac_address']}")


def _is_valid_ip(ip: str) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid IP address
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def _is_host_alive(target_ip: str, timeout: int = 3) -> bool:
    """
    Check if target host is alive using ICMP ping.
    
    Args:
        target_ip (str): Target IP address
        timeout (int): Timeout for ping in seconds
        
    Returns:
        bool: True if host is alive
    """
    try:
        # Send ICMP echo request
        packet = IP(dst=target_ip)/ICMP()
        reply = sr1(packet, timeout=timeout, verbose=0)
        
        return reply is not None
    except Exception as e:
        logger.debug(f"Host alive check failed for {target_ip}: {e}")
        return False


def _scan_port(target_ip: str, port: int, timeout: int) -> Dict[str, Any]:
    """
    Scan a single port using TCP SYN scan.
    
    Args:
        target_ip (str): Target IP address
        port (int): Port to scan
        timeout (int): Timeout for scan attempt
        
    Returns:
        dict: Port scan result
    """
    try:
        # Create TCP SYN packet
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        
        # Send packet and wait for response
        response = sr1(packet, timeout=timeout, verbose=0)
        
        if response is None:
            return {
                "port": port,
                "open": False,
                "service_info": {"service": "Closed", "banner": None}
            }
        
        # Check if port is open (SYN+ACK response)
        if response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            
            if tcp_layer.flags == 0x12:  # SYN+ACK
                # Port is open, try to grab banner
                banner = _grab_banner(target_ip, port, timeout=1)
                service = SERVICE_BANNERS.get(port, "Unknown")
                
                return {
                    "port": port,
                    "open": True,
                    "service_info": {
                        "service": service,
                        "banner": banner,
                        "port_state": "Open"
                    }
                }
            elif tcp_layer.flags == 0x14:  # RST+ACK
                return {
                    "port": port,
                    "open": False,
                    "service_info": {"service": "Closed", "banner": None}
                }
        
        return {
            "port": port,
            "open": False,
            "service_info": {"service": "Filtered", "banner": None}
        }
        
    except Exception as e:
        logger.debug(f"Error scanning port {port} on {target_ip}: {e}")
        return {
            "port": port,
            "open": False,
            "service_info": {"service": "Error", "banner": str(e)}
        }


def _grab_banner(target_ip: str, port: int, timeout: int = 1) -> str:
    """
    Attempt to grab service banner from open port.
    
    Args:
        target_ip (str): Target IP address
        port (int): Port to grab banner from
        timeout (int): Connection timeout in seconds
        
    Returns:
        str: Service banner or None if failed
    """
    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connect to the service
        sock.connect((target_ip, port))
        
        # Send a simple HTTP request for web services
        if port in [80, 8080]:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        elif port in [443, 8443]:
            # HTTPS services won't respond to plain HTTP
            sock.close()
            return "HTTPS Service"
        elif port == 22:
            # SSH typically sends banner automatically
            pass
        else:
            # For other services, try to get banner
            sock.send(b"\r\n")
        
        # Receive response
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return banner if banner else "No banner"
        
    except Exception as e:
        logger.debug(f"Banner grab failed for {target_ip}:{port}: {e}")
        return None


def quick_scan(target_ip: str) -> Dict[str, Any]:
    """
    Perform a quick scan on most common ports only.
    
    Args:
        target_ip (str): Target IP address to scan
        
    Returns:
        dict: Quick scan results
    """
    quick_ports = [21, 22, 23, 80, 443, 3389]
    return network_scan(target_ip, ports=quick_ports, timeout=2, max_threads=10)


def comprehensive_scan(target_ip: str) -> Dict[str, Any]:
    """
    Perform a comprehensive scan on all common ports.
    
    Args:
        target_ip (str): Target IP address to scan
        
    Returns:
        dict: Comprehensive scan results
    """
    # Extended port list for comprehensive scan
    extended_ports = COMMON_PORTS + [
        135,  # RPC
        139,  # NetBIOS
        445,  # SMB
        1434, # MSSQL Browser
        5060, # SIP
        5061, # SIP-TLS
        6379, # Redis
        27017 # MongoDB
    ]
    
    return network_scan(target_ip, ports=extended_ports, timeout=3, max_threads=100)
