#!/usr/bin/env python3
"""
Network Scanner Utility
Part of the AI-Driven Offensive Security Tool
"""

import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

class NetworkScanner:
    """Advanced network scanning utility."""
    
    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        
    def scan_port(self, host: str, port: int) -> Dict[str, Any]:
        """Scan a single port on a host."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            return {
                'host': host,
                'port': port,
                'open': result == 0,
                'service': self._get_service_name(port)
            }
        except Exception as e:
            return {
                'host': host,
                'port': port,
                'open': False,
                'error': str(e)
            }
    
    def scan_ports(self, host: str, ports: List[int], max_threads: int = 50) -> List[Dict[str, Any]]:
        """Scan multiple ports on a host concurrently."""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(self.scan_port, host, port) for port in ports]
            
            for future in futures:
                result = future.result()
                results.append(result)
        
        return results
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for a port."""
        services = {
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
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def ping_host(self, host: str) -> bool:
        """Check if a host is reachable."""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '2', host], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

# Example usage
if __name__ == "__main__":
    scanner = NetworkScanner()
    
    # Scan common ports on localhost
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080]
    
    print("Scanning localhost...")
    results = scanner.scan_ports("127.0.0.1", common_ports)
    
    for result in results:
        status = "OPEN" if result['open'] else "CLOSED"
        print(f"Port {result['port']}/{result['service']}: {status}")
