"""
Network Reconnaissance module for the Ultimate PI Tool.

This module provides functionality for network scanning, discovery,
and analysis using tools like Nmap.
"""

import os
import sys
import json
import subprocess
import re
import ipaddress
import socket
import time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import xml.etree.ElementTree as ET

console = Console()

class NetworkRecon:
    """Network Reconnaissance class for scanning and analyzing networks."""
    
    def __init__(self):
        """Initialize the Network Reconnaissance module."""
        self.nmap_path = self._find_nmap()
        self.wireshark_path = self._find_wireshark()
        self.netcat_path = self._find_netcat()
    
    def scan_host(self, target, scan_type="basic", output_file=None):
        """Scan a host or network using Nmap."""
        console.print(f"[bold blue]Scanning target:[/] {target}")
        
        if not self.nmap_path:
            console.print("[bold red]Error:[/] Nmap not found. Please install Nmap and try again.")
            return None
        
        # Validate target
        if not self._validate_target(target):
            console.print(f"[bold red]Error:[/] Invalid target: {target}")
            return None
        
        # Determine scan options based on scan type
        if scan_type.lower() == "basic":
            options = "-sV -sS -T4 -O -F"
        elif scan_type.lower() == "quick":
            options = "-T4 -F"
        elif scan_type.lower() == "comprehensive":
            options = "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53"
        elif scan_type.lower() == "stealth":
            options = "-sS -T2 -f -D RND:5 --data-length 24"
        elif scan_type.lower() == "vulnerability":
            options = "-sV --script vuln"
        else:
            console.print(f"[bold red]Error:[/] Unknown scan type: {scan_type}")
            return None
        
        # Determine output file
        xml_output = output_file if output_file else f"nmap_scan_{target.replace('/', '_').replace(' ', '_')}.xml"
        
        # Build command
        cmd = f"{self.nmap_path} {options} -oX {xml_output} {target}"
        
        console.print(f"[bold blue]Running command:[/] {cmd}")
        
        # Run scan with progress indicator
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=100)
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Simulate progress while scan is running
            while process.poll() is None:
                # Update progress
                progress.update(task, advance=1)
                if progress.tasks[0].completed >= 90:
                    progress.update(task, completed=90)
                time.sleep(1)
            
            # Complete progress
            progress.update(task, completed=100)
            
            stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error running Nmap:[/] {stderr}")
            return None
        
        # Parse results
        try:
            results = self._parse_nmap_xml(xml_output)
            self._display_scan_results(results)
            return results
        except Exception as e:
            console.print(f"[bold red]Error parsing Nmap results:[/] {str(e)}")
            return None
    
    def discover_network(self, network, method="ping", output_file=None):
        """Discover hosts on a network."""
        console.print(f"[bold blue]Discovering hosts on network:[/] {network}")
        
        if not self.nmap_path:
            console.print("[bold red]Error:[/] Nmap not found. Please install Nmap and try again.")
            return None
        
        # Validate network
        try:
            ipaddress.ip_network(network)
        except ValueError:
            console.print(f"[bold red]Error:[/] Invalid network: {network}")
            return None
        
        # Determine discovery options based on method
        if method.lower() == "ping":
            options = "-sn"
        elif method.lower() == "arp":
            options = "-sn -PR"
        elif method.lower() == "syn":
            options = "-sn -PS22,80,443,3389,8080"
        elif method.lower() == "udp":
            options = "-sn -PU53,161,162"
        elif method.lower() == "comprehensive":
            options = "-sn -PE -PP -PS21,22,23,25,80,113,443,8080 -PA80,443,3389 -PU53,161,162"
        else:
            console.print(f"[bold red]Error:[/] Unknown discovery method: {method}")
            return None
        
        # Determine output file
        xml_output = output_file if output_file else f"nmap_discovery_{network.replace('/', '_').replace(' ', '_')}.xml"
        
        # Build command
        cmd = f"{self.nmap_path} {options} -oX {xml_output} {network}"
        
        console.print(f"[bold blue]Running command:[/] {cmd}")
        
        # Run discovery with progress indicator
        with Progress() as progress:
            task = progress.add_task("[cyan]Discovering hosts...", total=100)
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Simulate progress while discovery is running
            while process.poll() is None:
                # Update progress
                progress.update(task, advance=2)
                if progress.tasks[0].completed >= 90:
                    progress.update(task, completed=90)
                time.sleep(1)
            
            # Complete progress
            progress.update(task, completed=100)
            
            stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error running Nmap:[/] {stderr}")
            return None
        
        # Parse results
        try:
            results = self._parse_nmap_xml(xml_output)
            self._display_discovery_results(results)
            return results
        except Exception as e:
            console.print(f"[bold red]Error parsing Nmap results:[/] {str(e)}")
            return None
    
    def scan_ports(self, target, ports="common", protocol="tcp", output_file=None):
        """Scan ports on a host."""
        console.print(f"[bold blue]Scanning ports on:[/] {target}")
        
        if not self.nmap_path:
            console.print("[bold red]Error:[/] Nmap not found. Please install Nmap and try again.")
            return None
        
        # Validate target
        if not self._validate_target(target):
            console.print(f"[bold red]Error:[/] Invalid target: {target}")
            return None
        
        # Determine port options
        if ports == "common":
            port_opt = "--top-ports 1000"
        elif ports == "all":
            port_opt = "-p-"
        elif ports == "well-known":
            port_opt = "-p 1-1024"
        elif re.match(r'^[0-9,\-]+$', ports):
            port_opt = f"-p {ports}"
        else:
            console.print(f"[bold red]Error:[/] Invalid port specification: {ports}")
            return None
        
        # Determine protocol options
        if protocol.lower() == "tcp":
            proto_opt = "-sS"
        elif protocol.lower() == "udp":
            proto_opt = "-sU"
        elif protocol.lower() == "both":
            proto_opt = "-sS -sU"
        else:
            console.print(f"[bold red]Error:[/] Invalid protocol: {protocol}")
            return None
        
        # Determine output file
        xml_output = output_file if output_file else f"nmap_ports_{target.replace('/', '_').replace(' ', '_')}.xml"
        
        # Build command
        cmd = f"{self.nmap_path} {proto_opt} {port_opt} -sV --version-intensity 2 -oX {xml_output} {target}"
        
        console.print(f"[bold blue]Running command:[/] {cmd}")
        
        # Run scan with progress indicator
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning ports...", total=100)
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Simulate progress while scan is running
            while process.poll() is None:
                # Update progress
                progress.update(task, advance=1)
                if progress.tasks[0].completed >= 90:
                    progress.update(task, completed=90)
                time.sleep(1)
            
            # Complete progress
            progress.update(task, completed=100)
            
            stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error running Nmap:[/] {stderr}")
            return None
        
        # Parse results
        try:
            results = self._parse_nmap_xml(xml_output)
            self._display_port_results(results)
            return results
        except Exception as e:
            console.print(f"[bold red]Error parsing Nmap results:[/] {str(e)}")
            return None
    
    def os_detection(self, target, output_file=None):
        """Detect operating system of a host."""
        console.print(f"[bold blue]Detecting operating system on:[/] {target}")
        
        if not self.nmap_path:
            console.print("[bold red]Error:[/] Nmap not found. Please install Nmap and try again.")
            return None
        
        # Validate target
        if not self._validate_target(target):
            console.print(f"[bold red]Error:[/] Invalid target: {target}")
            return None
        
        # Determine output file
        xml_output = output_file if output_file else f"nmap_os_{target.replace('/', '_').replace(' ', '_')}.xml"
        
        # Build command
        cmd = f"{self.nmap_path} -O -T4 --osscan-guess -oX {xml_output} {target}"
        
        console.print(f"[bold blue]Running command:[/] {cmd}")
        
        # Run scan with progress indicator
        with Progress() as progress:
            task = progress.add_task("[cyan]Detecting OS...", total=100)
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Simulate progress while scan is running
            while process.poll() is None:
                # Update progress
                progress.update(task, advance=2)
                if progress.tasks[0].completed >= 90:
                    progress.update(task, completed=90)
                time.sleep(1)
            
            # Complete progress
            progress.update(task, completed=100)
            
            stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error running Nmap:[/] {stderr}")
            return None
        
        # Parse results
        try:
            results = self._parse_nmap_xml(xml_output)
            self._display_os_results(results)
            return results
        except Exception as e:
            console.print(f"[bold red]Error parsing Nmap results:[/] {str(e)}")
            return None
    
    def vulnerability_scan(self, target, output_file=None):
        """Scan for vulnerabilities on a host."""
        console.print(f"[bold blue]Scanning for vulnerabilities on:[/] {target}")
        
        if not self.nmap_path:
            console.print("[bold red]Error:[/] Nmap not found. Please install Nmap and try again.")
            return None
        
        # Validate target
        if not self._validate_target(target):
            console.print(f"[bold red]Error:[/] Invalid target: {target}")
            return None
        
        # Determine output file
        xml_output = output_file if output_file else f"nmap_vuln_{target.replace('/', '_').replace(' ', '_')}.xml"
        
        # Build command
        cmd = f"{self.nmap_path} -sV --script vuln -oX {xml_output} {target}"
        
        console.print(f"[bold blue]Running command:[/] {cmd}")
        
        # Run scan with progress indicator
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning for vulnerabilities...", total=100)
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Simulate progress while scan is running
            while process.poll() is None:
                # Update progress
                progress.update(task, advance=0.5)
                if progress.tasks[0].completed >= 90:
                    progress.update(task, completed=90)
                time.sleep(1)
            
            # Complete progress
            progress.update(task, completed=100)
            
            stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error running Nmap:[/] {stderr}")
            return None
        
        # Parse results
        try:
            results = self._parse_nmap_xml(xml_output)
            self._display_vulnerability_results(results)
            return results
        except Exception as e:
            console.print(f"[bold red]Error parsing Nmap results:[/] {str(e)}")
            return None
    
    def dns_enumeration(self, domain, output_file=None):
        """Enumerate DNS information for a domain."""
        console.print(f"[bold blue]Enumerating DNS for domain:[/] {domain}")
        
        if not self.nmap_path:
            console.print("[bold red]Error:[/] Nmap not found. Please install Nmap and try again.")
            return None
        
        # Determine output file
        xml_output = output_file if output_file else f"nmap_dns_{domain.replace('/', '_').replace(' ', '_')}.xml"
        
        # Build command
        cmd = f"{self.nmap_path} --script dns-brute,dns-srv-enum,dns-zone-transfer -oX {xml_output} {domain}"
        
        console.print(f"[bold blue]Running command:[/] {cmd}")
        
        # Run scan with progress indicator
        with Progress() as progress:
            task = progress.add_task("[cyan]Enumerating DNS...", total=100)
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Simulate progress while scan is running
            while process.poll() is None:
                # Update progress
                progress.update(task, advance=1)
                if progress.tasks[0].completed >= 90:
                    progress.update(task, completed=90)
                time.sleep(1)
            
            # Complete progress
            progress.update(task, completed=100)
            
            stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error running Nmap:[/] {stderr}")
            return None
        
        # Parse results
        try:
            results = self._parse_nmap_xml(xml_output)
            self._display_dns_results(results)
            return results
        except Exception as e:
            console.print(f"[bold red]Error parsing Nmap results:[/] {str(e)}")
            return None
    
    def capture_packets(self, interface, filter="", count=100, output_file=None):
        """Capture network packets using tcpdump or tshark."""
        console.print(f"[bold blue]Capturing packets on interface:[/] {interface}")
        
        # Check for tcpdump or tshark
        tcpdump_path = self._find_tcpdump()
        tshark_path = self._find_tshark()
        
        if not tcpdump_path and not tshark_path:
            console.print("[bold red]Error:[/] Neither tcpdump nor tshark found. Please install one of them and try again.")
            return None
        
        # Determine output file
        pcap_output = output_file if output_file else f"packet_capture_{interface}_{int(time.time())}.pcap"
        
        # Build command
        if tcpdump_path:
            cmd = f"{tcpdump_path} -i {interface} -c {count} -w {pcap_output}"
            if filter:
                cmd += f" '{filter}'"
        else:
            cmd = f"{tshark_path} -i {interface} -c {count} -w {pcap_output}"
            if filter:
                cmd += f" -f '{filter}'"
        
        console.print(f"[bold blue]Running command:[/] {cmd}")
        
        # Run capture with progress indicator
        with Progress() as progress:
            task = progress.add_task("[cyan]Capturing packets...", total=count)
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Simulate progress while capture is running
            captured = 0
            while process.poll() is None and captured < count:
                # Update progress
                captured += 1
                progress.update(task, completed=captured)
                time.sleep(0.1)
            
            # Complete progress
            progress.update(task, completed=count)
            
            stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error capturing packets:[/] {stderr}")
            return None
        
        console.print(f"[bold green]Packet capture completed:[/] {pcap_output}")
        return pcap_output
    
    def analyze_pcap(self, pcap_file):
        """Analyze a PCAP file using tshark."""
        console.print(f"[bold blue]Analyzing PCAP file:[/] {pcap_file}")
        
        # Check for tshark
        tshark_path = self._find_tshark()
        
        if not tshark_path:
            console.print("[bold red]Error:[/] tshark not found. Please install Wireshark/tshark and try again.")
            return None
        
        # Build command for protocol summary
        cmd_proto = f"{tshark_path} -r {pcap_file} -q -z io,phs"
        
        console.print("[bold blue]Generating protocol summary...[/]")
        
        # Run protocol summary
        process = subprocess.Popen(
            cmd_proto,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error analyzing PCAP:[/] {stderr}")
            return None
        
        # Display protocol summary
        console.print("[bold green]Protocol Hierarchy Statistics:[/]")
        console.print(stdout)
        
        # Build command for conversation summary
        cmd_conv = f"{tshark_path} -r {pcap_file} -q -z conv,ip"
        
        console.print("[bold blue]Generating conversation summary...[/]")
        
        # Run conversation summary
        process = subprocess.Popen(
            cmd_conv,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error analyzing PCAP:[/] {stderr}")
        else:
            # Display conversation summary
            console.print("[bold green]IP Conversations:[/]")
            console.print(stdout)
        
        # Build command for HTTP summary if present
        cmd_http = f"{tshark_path} -r {pcap_file} -Y http -T fields -e http.request.method -e http.request.uri -e http.host -e http.response.code"
        
        console.print("[bold blue]Extracting HTTP requests...[/]")
        
        # Run HTTP summary
        process = subprocess.Popen(
            cmd_http,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error extracting HTTP requests:[/] {stderr}")
        elif stdout.strip():
            # Display HTTP summary
            console.print("[bold green]HTTP Requests:[/]")
            
            # Create table
            table = Table(title="HTTP Requests")
            table.add_column("Method", style="cyan")
            table.add_column("Host", style="green")
            table.add_column("URI", style="yellow")
            table.add_column("Response", style="magenta")
            
            for line in stdout.strip().split('\n'):
                parts = line.strip().split('\t')
                if len(parts) >= 3:
                    method = parts[0] if parts[0] else "N/A"
                    uri = parts[1] if parts[1] else "N/A"
                    host = parts[2] if parts[2] else "N/A"
                    response = parts[3] if len(parts) > 3 and parts[3] else "N/A"
                    
                    table.add_row(method, host, uri, response)
            
            console.print(table)
        
        return {
            "pcap_file": pcap_file,
            "protocol_summary": stdout,
            "conversation_summary": stdout
        }
    
    def trace_route(self, target, max_hops=30):
        """Trace the route to a target."""
        console.print(f"[bold blue]Tracing route to:[/] {target}")
        
        # Validate target
        if not self._validate_target(target):
            console.print(f"[bold red]Error:[/] Invalid target: {target}")
            return None
        
        # Determine command based on OS
        if os.name == 'nt':  # Windows
            cmd = f"tracert -d -h {max_hops} {target}"
        else:  # Unix/Linux
            cmd = f"traceroute -n -m {max_hops} {target}"
        
        console.print(f"[bold blue]Running command:[/] {cmd}")
        
        # Run traceroute
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            console.print(f"[bold red]Error running traceroute:[/] {stderr}")
            return None
        
        # Display results
        console.print("[bold green]Traceroute Results:[/]")
        console.print(stdout)
        
        # Parse results
        hops = []
        
        if os.name == 'nt':  # Windows output
            for line in stdout.split('\n'):
                match = re.search(r'^\s*(\d+)\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(\S+)', line)
                if match:
                    hop_num = int(match.group(1))
                    times = [int(match.group(2)), int(match.group(3)), int(match.group(4))]
                    ip = match.group(5)
                    
                    hops.append({
                        "hop": hop_num,
                        "ip": ip,
                        "times": times,
                        "avg_time": sum(times) / len(times)
                    })
        else:  # Unix/Linux output
            for line in stdout.split('\n'):
                match = re.search(r'^\s*(\d+)\s+(\S+)\s+(\d+\.\d+)\s+ms\s+(\d+\.\d+)\s+ms\s+(\d+\.\d+)\s+ms', line)
                if match:
                    hop_num = int(match.group(1))
                    ip = match.group(2)
                    times = [float(match.group(3)), float(match.group(4)), float(match.group(5))]
                    
                    hops.append({
                        "hop": hop_num,
                        "ip": ip,
                        "times": times,
                        "avg_time": sum(times) / len(times)
                    })
        
        return {
            "target": target,
            "hops": hops,
            "raw_output": stdout
        }
    
    def _find_nmap(self):
        """Find the path to the Nmap executable."""
        # Check if nmap is in PATH
        try:
            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    "where nmap",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:  # Unix/Linux
                process = subprocess.Popen(
                    "which nmap",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            
            stdout, stderr = process.communicate()
            
            if process.returncode == 0 and stdout.strip():
                return stdout.strip().split('\n')[0]
            
            # Check common installation locations
            common_paths = []
            
            if os.name == 'nt':  # Windows
                common_paths = [
                    r"C:\Program Files (x86)\Nmap\nmap.exe",
                    r"C:\Program Files\Nmap\nmap.exe"
                ]
            else:  # Unix/Linux
                common_paths = [
                    "/usr/bin/nmap",
                    "/usr/local/bin/nmap",
                    "/opt/local/bin/nmap"
                ]
            
            for path in common_paths:
                if os.path.isfile(path):
                    return path
            
            # Not found
            console.print("[bold yellow]Warning:[/] Nmap not found. Some functionality will be limited.")
            return None
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Error finding Nmap: {str(e)}")
            return None
    
    def _find_wireshark(self):
        """Find the path to the Wireshark executable."""
        # Check if wireshark is in PATH
        try:
            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    "where wireshark",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:  # Unix/Linux
                process = subprocess.Popen(
                    "which wireshark",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            
            stdout, stderr = process.communicate()
            
            if process.returncode == 0 and stdout.strip():
                return stdout.strip().split('\n')[0]
            
            # Check common installation locations
            common_paths = []
            
            if os.name == 'nt':  # Windows
                common_paths = [
                    r"C:\Program Files\Wireshark\wireshark.exe",
                    r"C:\Program Files (x86)\Wireshark\wireshark.exe"
                ]
            else:  # Unix/Linux
                common_paths = [
                    "/usr/bin/wireshark",
                    "/usr/local/bin/wireshark",
                    "/opt/local/bin/wireshark"
                ]
            
            for path in common_paths:
                if os.path.isfile(path):
                    return path
            
            # Not found
            console.print("[bold yellow]Warning:[/] Wireshark not found. Some functionality will be limited.")
            return None
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Error finding Wireshark: {str(e)}")
            return None
    
    def _find_netcat(self):
        """Find the path to the Netcat executable."""
        # Check if netcat/nc is in PATH
        try:
            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    "where nc",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:  # Unix/Linux
                process = subprocess.Popen(
                    "which nc || which netcat",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            
            stdout, stderr = process.communicate()
            
            if process.returncode == 0 and stdout.strip():
                return stdout.strip().split('\n')[0]
            
            # Check common installation locations
            common_paths = []
            
            if os.name == 'nt':  # Windows
                common_paths = [
                    r"C:\Windows\System32\nc.exe",
                    r"C:\Program Files\Netcat\nc.exe",
                    r"C:\Program Files (x86)\Netcat\nc.exe"
                ]
            else:  # Unix/Linux
                common_paths = [
                    "/bin/nc",
                    "/usr/bin/nc",
                    "/usr/local/bin/nc",
                    "/bin/netcat",
                    "/usr/bin/netcat",
                    "/usr/local/bin/netcat"
                ]
            
            for path in common_paths:
                if os.path.isfile(path):
                    return path
            
            # Not found
            console.print("[bold yellow]Warning:[/] Netcat not found. Some functionality will be limited.")
            return None
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Error finding Netcat: {str(e)}")
            return None
    
    def _find_tcpdump(self):
        """Find the path to the tcpdump executable."""
        # Only relevant on Unix/Linux
        if os.name == 'nt':  # Windows
            return None
        
        # Check if tcpdump is in PATH
        try:
            process = subprocess.Popen(
                "which tcpdump",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode == 0 and stdout.strip():
                return stdout.strip()
            
            # Check common installation locations
            common_paths = [
                "/usr/bin/tcpdump",
                "/usr/local/bin/tcpdump",
                "/opt/local/bin/tcpdump",
                "/sbin/tcpdump"
            ]
            
            for path in common_paths:
                if os.path.isfile(path):
                    return path
            
            # Not found
            return None
            
        except Exception:
            return None
    
    def _find_tshark(self):
        """Find the path to the tshark executable."""
        # Check if tshark is in PATH
        try:
            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    "where tshark",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:  # Unix/Linux
                process = subprocess.Popen(
                    "which tshark",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            
            stdout, stderr = process.communicate()
            
            if process.returncode == 0 and stdout.strip():
                return stdout.strip().split('\n')[0]
            
            # Check common installation locations
            common_paths = []
            
            if os.name == 'nt':  # Windows
                common_paths = [
                    r"C:\Program Files\Wireshark\tshark.exe",
                    r"C:\Program Files (x86)\Wireshark\tshark.exe"
                ]
            else:  # Unix/Linux
                common_paths = [
                    "/usr/bin/tshark",
                    "/usr/local/bin/tshark",
                    "/opt/local/bin/tshark"
                ]
            
            for path in common_paths:
                if os.path.isfile(path):
                    return path
            
            # Not found
            return None
            
        except Exception:
            return None
    
    def _validate_target(self, target):
        """Validate a target (IP address, hostname, or CIDR range)."""
        # Check if target is an IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Check if target is a CIDR range
        try:
            ipaddress.ip_network(target)
            return True
        except ValueError:
            pass
        
        # Check if target is a hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.error:
            pass
        
        # Not a valid target
        return False
    
    def _parse_nmap_xml(self, xml_file):
        """Parse Nmap XML output file."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Extract scan information
            scan_info = {
                "scanner": root.get("scanner", ""),
                "args": root.get("args", ""),
                "start": root.get("start", ""),
                "version": root.get("version", ""),
                "hosts": []
            }
            
            # Extract host information
            for host in root.findall(".//host"):
                host_info = {
                    "status": host.find("status").get("state", "") if host.find("status") is not None else "",
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                    "os": []
                }
                
                # Extract addresses
                for addr in host.findall(".//address"):
                    host_info["addresses"].append({
                        "addr": addr.get("addr", ""),
                        "addrtype": addr.get("addrtype", ""),
                        "vendor": addr.get("vendor", "")
                    })
                
                # Extract hostnames
                for hostname in host.findall(".//hostname"):
                    host_info["hostnames"].append({
                        "name": hostname.get("name", ""),
                        "type": hostname.get("type", "")
                    })
                
                # Extract ports
                for port in host.findall(".//port"):
                    port_info = {
                        "protocol": port.get("protocol", ""),
                        "portid": port.get("portid", ""),
                        "state": port.find("state").get("state", "") if port.find("state") is not None else "",
                        "service": {
                            "name": port.find("service").get("name", "") if port.find("service") is not None else "",
                            "product": port.find("service").get("product", "") if port.find("service") is not None else "",
                            "version": port.find("service").get("version", "") if port.find("service") is not None else "",
                            "extrainfo": port.find("service").get("extrainfo", "") if port.find("service") is not None else ""
                        },
                        "scripts": []
                    }
                    
                    # Extract script output
                    for script in port.findall(".//script"):
                        port_info["scripts"].append({
                            "id": script.get("id", ""),
                            "output": script.get("output", "")
                        })
                    
                    host_info["ports"].append(port_info)
                
                # Extract OS detection
                for os in host.findall(".//os"):
                    for match in os.findall(".//osmatch"):
                        os_info = {
                            "name": match.get("name", ""),
                            "accuracy": match.get("accuracy", ""),
                            "osclass": []
                        }
                        
                        for osclass in match.findall(".//osclass"):
                            os_info["osclass"].append({
                                "type": osclass.get("type", ""),
                                "vendor": osclass.get("vendor", ""),
                                "osfamily": osclass.get("osfamily", ""),
                                "osgen": osclass.get("osgen", ""),
                                "accuracy": osclass.get("accuracy", "")
                            })
                        
                        host_info["os"].append(os_info)
                
                # Extract script output at host level
                host_info["scripts"] = []
                for script in host.findall(".//hostscript/script"):
                    host_info["scripts"].append({
                        "id": script.get("id", ""),
                        "output": script.get("output", "")
                    })
                
                scan_info["hosts"].append(host_info)
            
            return scan_info
            
        except Exception as e:
            console.print(f"[bold red]Error parsing XML:[/] {str(e)}")
            return None
    
    def _display_scan_results(self, results):
        """Display scan results in a readable format."""
        if not results:
            return
        
        console.print(f"[bold green]Scan completed with Nmap {results['version']}[/]")
        console.print(f"[bold blue]Command:[/] {results['args']}")
        
        # Display host information
        for host in results["hosts"]:
            # Get IP address
            ip = next((addr["addr"] for addr in host["addresses"] if addr["addrtype"] == "ipv4"), "Unknown")
            
            # Get hostname
            hostname = next((name["name"] for name in host["hostnames"] if name["name"]), ip)
            
            console.print(f"\n[bold green]Host: {hostname} ({ip})[/] - [bold]{host['status']}[/]")
            
            # Display OS information if available
            if host["os"]:
                os_table = Table(title="Operating System Detection")
                os_table.add_column("Name", style="cyan")
                os_table.add_column("Accuracy", style="green")
                os_table.add_column("Type", style="yellow")
                os_table.add_column("Family", style="magenta")
                
                for os in host["os"]:
                    name = os["name"]
                    accuracy = os["accuracy"]
                    
                    if os["osclass"]:
                        os_type = os["osclass"][0]["type"]
                        os_family = os["osclass"][0]["osfamily"]
                    else:
                        os_type = "Unknown"
                        os_family = "Unknown"
                    
                    os_table.add_row(name, accuracy, os_type, os_family)
                
                console.print(os_table)
            
            # Display port information
            if host["ports"]:
                port_table = Table(title="Open Ports")
                port_table.add_column("Port", style="cyan")
                port_table.add_column("Protocol", style="green")
                port_table.add_column("State", style="yellow")
                port_table.add_column("Service", style="magenta")
                port_table.add_column("Version", style="blue")
                
                for port in host["ports"]:
                    if port["state"] == "open":
                        port_id = port["portid"]
                        protocol = port["protocol"]
                        state = port["state"]
                        service = port["service"]["name"]
                        version = f"{port['service']['product']} {port['service']['version']}".strip()
                        
                        port_table.add_row(port_id, protocol, state, service, version)
                
                console.print(port_table)
            
            # Display script output if available
            if host["scripts"]:
                script_table = Table(title="Script Results")
                script_table.add_column("Script", style="cyan")
                script_table.add_column("Output", style="green")
                
                for script in host["scripts"]:
                    script_id = script["id"]
                    output = script["output"]
                    
                    script_table.add_row(script_id, output)
                
                console.print(script_table)
    
    def _display_discovery_results(self, results):
        """Display network discovery results in a readable format."""
        if not results:
            return
        
        console.print(f"[bold green]Network Discovery completed with Nmap {results['version']}[/]")
        console.print(f"[bold blue]Command:[/] {results['args']}")
        
        # Count hosts by status
        up_hosts = [host for host in results["hosts"] if host["status"] == "up"]
        down_hosts = [host for host in results["hosts"] if host["status"] == "down"]
        
        console.print(f"\n[bold green]Found {len(up_hosts)} hosts up and {len(down_hosts)} hosts down[/]")
        
        # Display host information
        if up_hosts:
            host_table = Table(title="Discovered Hosts")
            host_table.add_column("IP Address", style="cyan")
            host_table.add_column("Hostname", style="green")
            host_table.add_column("MAC Address", style="yellow")
            host_table.add_column("Vendor", style="magenta")
            
            for host in up_hosts:
                # Get IP address
                ip = next((addr["addr"] for addr in host["addresses"] if addr["addrtype"] == "ipv4"), "Unknown")
                
                # Get hostname
                hostname = next((name["name"] for name in host["hostnames"] if name["name"]), "")
                
                # Get MAC address
                mac = next((addr["addr"] for addr in host["addresses"] if addr["addrtype"] == "mac"), "")
                
                # Get vendor
                vendor = next((addr["vendor"] for addr in host["addresses"] if addr["addrtype"] == "mac" and "vendor" in addr), "")
                
                host_table.add_row(ip, hostname, mac, vendor)
            
            console.print(host_table)
    
    def _display_port_results(self, results):
        """Display port scan results in a readable format."""
        if not results:
            return
        
        console.print(f"[bold green]Port Scan completed with Nmap {results['version']}[/]")
        console.print(f"[bold blue]Command:[/] {results['args']}")
        
        # Display port information for each host
        for host in results["hosts"]:
            # Get IP address
            ip = next((addr["addr"] for addr in host["addresses"] if addr["addrtype"] == "ipv4"), "Unknown")
            
            # Get hostname
            hostname = next((name["name"] for name in host["hostnames"] if name["name"]), ip)
            
            console.print(f"\n[bold green]Host: {hostname} ({ip})[/] - [bold]{host['status']}[/]")
            
            # Display port information
            if host["ports"]:
                port_table = Table(title="Port Scan Results")
                port_table.add_column("Port", style="cyan")
                port_table.add_column("Protocol", style="green")
                port_table.add_column("State", style="yellow")
                port_table.add_column("Service", style="magenta")
                port_table.add_column("Version", style="blue")
                
                for port in host["ports"]:
                    port_id = port["portid"]
                    protocol = port["protocol"]
                    state = port["state"]
                    service = port["service"]["name"]
                    version = f"{port['service']['product']} {port['service']['version']}".strip()
                    
                    port_table.add_row(port_id, protocol, state, service, version)
                
                console.print(port_table)
    
    def _display_os_results(self, results):
        """Display OS detection results in a readable format."""
        if not results:
            return
        
        console.print(f"[bold green]OS Detection completed with Nmap {results['version']}[/]")
        console.print(f"[bold blue]Command:[/] {results['args']}")
        
        # Display OS information for each host
        for host in results["hosts"]:
            # Get IP address
            ip = next((addr["addr"] for addr in host["addresses"] if addr["addrtype"] == "ipv4"), "Unknown")
            
            # Get hostname
            hostname = next((name["name"] for name in host["hostnames"] if name["name"]), ip)
            
            console.print(f"\n[bold green]Host: {hostname} ({ip})[/] - [bold]{host['status']}[/]")
            
            # Display OS information
            if host["os"]:
                os_table = Table(title="Operating System Detection")
                os_table.add_column("Name", style="cyan")
                os_table.add_column("Accuracy", style="green")
                os_table.add_column("Type", style="yellow")
                os_table.add_column("Family", style="magenta")
                os_table.add_column("Generation", style="blue")
                
                for os in host["os"]:
                    name = os["name"]
                    accuracy = os["accuracy"]
                    
                    if os["osclass"]:
                        os_type = os["osclass"][0]["type"]
                        os_family = os["osclass"][0]["osfamily"]
                        os_gen = os["osclass"][0]["osgen"]
                    else:
                        os_type = "Unknown"
                        os_family = "Unknown"
                        os_gen = "Unknown"
                    
                    os_table.add_row(name, accuracy, os_type, os_family, os_gen)
                
                console.print(os_table)
            else:
                console.print("[bold yellow]No OS information available[/]")
    
    def _display_vulnerability_results(self, results):
        """Display vulnerability scan results in a readable format."""
        if not results:
            return
        
        console.print(f"[bold green]Vulnerability Scan completed with Nmap {results['version']}[/]")
        console.print(f"[bold blue]Command:[/] {results['args']}")
        
        # Display vulnerability information for each host
        for host in results["hosts"]:
            # Get IP address
            ip = next((addr["addr"] for addr in host["addresses"] if addr["addrtype"] == "ipv4"), "Unknown")
            
            # Get hostname
            hostname = next((name["name"] for name in host["hostnames"] if name["name"]), ip)
            
            console.print(f"\n[bold green]Host: {hostname} ({ip})[/] - [bold]{host['status']}[/]")
            
            # Collect all script results (both host and port level)
            all_scripts = host["scripts"].copy()
            
            for port in host["ports"]:
                for script in port["scripts"]:
                    all_scripts.append({
                        "id": script["id"],
                        "output": script["output"],
                        "port": f"{port['protocol']}/{port['portid']}"
                    })
            
            # Display vulnerability information
            if all_scripts:
                vuln_table = Table(title="Vulnerability Scan Results")
                vuln_table.add_column("Script", style="cyan")
                vuln_table.add_column("Port", style="green")
                vuln_table.add_column("Finding", style="yellow")
                
                for script in all_scripts:
                    script_id = script["id"]
                    output = script["output"].strip()
                    port = script.get("port", "host")
                    
                    # Truncate long output
                    if len(output) > 100:
                        output = output[:97] + "..."
                    
                    vuln_table.add_row(script_id, port, output)
                
                console.print(vuln_table)
            else:
                console.print("[bold yellow]No vulnerability information available[/]")
    
    def _display_dns_results(self, results):
        """Display DNS enumeration results in a readable format."""
        if not results:
            return
        
        console.print(f"[bold green]DNS Enumeration completed with Nmap {results['version']}[/]")
        console.print(f"[bold blue]Command:[/] {results['args']}")
        
        # Display DNS information for each host
        for host in results["hosts"]:
            # Get hostname
            hostname = next((name["name"] for name in host["hostnames"] if name["name"]), "Unknown")
            
            console.print(f"\n[bold green]Domain: {hostname}[/]")
            
            # Collect all script results
            all_scripts = host["scripts"].copy()
            
            # Display DNS information
            if all_scripts:
                dns_table = Table(title="DNS Enumeration Results")
                dns_table.add_column("Script", style="cyan")
                dns_table.add_column("Finding", style="yellow")
                
                for script in all_scripts:
                    script_id = script["id"]
                    output = script["output"].strip()
                    
                    dns_table.add_row(script_id, output)
                
                console.print(dns_table)
            else:
                console.print("[bold yellow]No DNS information available[/]")
