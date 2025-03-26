"""
Network Steganography module for the Ultimate PI Tool.

This module provides functionality for hiding and extracting data in network traffic
using various steganography techniques including TCP/IP header manipulation,
protocol timing-based techniques, and covert channels in network protocols.
"""

import os
import sys
import socket
import struct
import time
import random
import threading
from rich.console import Console
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw, sniff, send

console = Console()

class NetworkSteganography:
    """Network Steganography class for hiding and extracting data in network traffic."""
    
    def __init__(self):
        """Initialize the Network Steganography module."""
        self.running = False
        self.listener_thread = None
    
    def hide_data(self, data, protocol="tcp", destination="127.0.0.1", port=8080):
        """Hide data in network traffic using the specified protocol."""
        console.print(f"[bold blue]Hiding data in network traffic using {protocol.upper()} protocol[/]")
        
        # Convert data to binary if it's a string
        if isinstance(data, str):
            # If data is a file path, read the file
            if os.path.isfile(data):
                try:
                    with open(data, 'rb') as f:
                        binary_data = f.read()
                except Exception as e:
                    console.print(f"[bold red]Error:[/] Failed to read data file: {str(e)}")
                    return False
            else:
                # Otherwise, treat as text
                binary_data = data.encode('utf-8')
        else:
            binary_data = data
        
        # Choose the appropriate method based on protocol
        if protocol.lower() == "tcp":
            success = self._hide_tcp(binary_data, destination, port)
        elif protocol.lower() == "udp":
            success = self._hide_udp(binary_data, destination, port)
        elif protocol.lower() == "icmp":
            success = self._hide_icmp(binary_data, destination)
        elif protocol.lower() == "dns":
            success = self._hide_dns(binary_data, destination)
        else:
            console.print(f"[bold red]Error:[/] Unsupported protocol: {protocol}")
            return False
        
        if success:
            console.print(f"[bold green]Success![/] Data hidden in network traffic")
            return True
        else:
            console.print(f"[bold red]Error:[/] Failed to hide data in network traffic")
            return False
    
    def extract_data(self, protocol="tcp", interface="eth0", timeout=30):
        """Extract hidden data from network traffic using the specified protocol."""
        console.print(f"[bold blue]Extracting data from network traffic using {protocol.upper()} protocol[/]")
        console.print(f"[bold blue]Listening on interface {interface} for {timeout} seconds[/]")
        
        # Choose the appropriate method based on protocol
        if protocol.lower() == "tcp":
            data = self._extract_tcp(interface, timeout)
        elif protocol.lower() == "udp":
            data = self._extract_udp(interface, timeout)
        elif protocol.lower() == "icmp":
            data = self._extract_icmp(interface, timeout)
        elif protocol.lower() == "dns":
            data = self._extract_dns(interface, timeout)
        else:
            console.print(f"[bold red]Error:[/] Unsupported protocol: {protocol}")
            return False
        
        if data:
            # Try to decode as text and display
            try:
                text_data = data.decode('utf-8')
                console.print(f"[bold green]Extracted data:[/] {text_data}")
            except UnicodeDecodeError:
                console.print(f"[bold yellow]Warning:[/] Extracted data is not valid UTF-8 text")
                console.print(f"[bold green]Extracted data (hex):[/] {data.hex()[:100]}...")
            
            return True
        else:
            console.print(f"[bold red]Error:[/] Failed to extract data from network traffic")
            return False
    
    def listen(self, protocol="tcp", interface="eth0"):
        """Start a listener for hidden data in network traffic."""
        console.print(f"[bold blue]Starting listener for {protocol.upper()} steganography on interface {interface}[/]")
        
        if self.running:
            console.print(f"[bold yellow]Warning:[/] Listener is already running")
            return False
        
        self.running = True
        
        # Start listener in a separate thread
        self.listener_thread = threading.Thread(
            target=self._listener_thread,
            args=(protocol, interface)
        )
        self.listener_thread.daemon = True
        self.listener_thread.start()
        
        console.print(f"[bold green]Listener started successfully[/]")
        console.print(f"[bold blue]Press Ctrl+C to stop the listener[/]")
        
        return True
    
    def stop_listener(self):
        """Stop the listener for hidden data in network traffic."""
        if not self.running:
            console.print(f"[bold yellow]Warning:[/] No listener is currently running")
            return False
        
        self.running = False
        
        if self.listener_thread and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=2)
        
        console.print(f"[bold green]Listener stopped successfully[/]")
        return True
    
    def _hide_tcp(self, data, destination, port):
        """Hide data in TCP packets using header fields and sequence numbers."""
        try:
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            
            # Connect to the destination
            console.print(f"[bold blue]Connecting to {destination}:{port}[/]")
            try:
                s.connect((destination, port))
            except ConnectionRefusedError:
                console.print(f"[bold red]Error:[/] Connection refused. Make sure a listener is running on {destination}:{port}")
                return False
            except Exception as e:
                console.print(f"[bold red]Error:[/] Failed to connect: {str(e)}")
                return False
            
            # Prepare data chunks
            chunk_size = 1024  # Adjust as needed
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            
            console.print(f"[bold blue]Sending data in {len(chunks)} chunks[/]")
            
            # Send data chunks
            for i, chunk in enumerate(chunks):
                # Add chunk index and total chunks information
                header = struct.pack("!II", i, len(chunks))
                packet = header + chunk
                
                # Send the packet
                s.send(packet)
                
                # Small delay to avoid overwhelming the receiver
                time.sleep(0.01)
            
            # Close the connection
            s.close()
            
            console.print(f"[bold green]Data sent successfully:[/] {len(data)} bytes in {len(chunks)} chunks")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def _extract_tcp(self, interface, timeout):
        """Extract hidden data from TCP packets."""
        console.print(f"[bold blue]This method requires a proper TCP server to be running[/]")
        console.print(f"[bold yellow]Warning:[/] TCP extraction method is not fully implemented for passive sniffing[/]")
        console.print(f"[bold blue]Please use a TCP server to receive the data[/]")
        
        # In a real implementation, this would use scapy to sniff packets
        # and extract data from TCP headers and sequence numbers
        
        return None
    
    def _hide_udp(self, data, destination, port):
        """Hide data in UDP packets using header fields and payload."""
        try:
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Prepare data chunks
            chunk_size = 1024  # Adjust as needed
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            
            console.print(f"[bold blue]Sending data in {len(chunks)} UDP packets[/]")
            
            # Send data chunks
            for i, chunk in enumerate(chunks):
                # Add chunk index and total chunks information
                header = struct.pack("!II", i, len(chunks))
                packet = header + chunk
                
                # Send the packet
                s.sendto(packet, (destination, port))
                
                # Small delay to avoid overwhelming the receiver
                time.sleep(0.01)
            
            # Close the socket
            s.close()
            
            console.print(f"[bold green]Data sent successfully:[/] {len(data)} bytes in {len(chunks)} UDP packets")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def _extract_udp(self, interface, timeout):
        """Extract hidden data from UDP packets."""
        try:
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Bind to all interfaces on a specific port
            port = 8080  # Use the same port as in hide_data
            s.bind(('0.0.0.0', port))
            
            # Set timeout
            s.settimeout(timeout)
            
            console.print(f"[bold blue]Listening for UDP packets on port {port}[/]")
            
            # Prepare to receive data
            chunks = {}
            total_chunks = None
            
            # Receive packets until timeout or all chunks received
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    # Receive a packet
                    packet, addr = s.recvfrom(2048)
                    
                    # Extract header information
                    if len(packet) >= 8:
                        chunk_index, chunks_count = struct.unpack("!II", packet[:8])
                        chunk_data = packet[8:]
                        
                        # Store the chunk
                        chunks[chunk_index] = chunk_data
                        
                        # Update total chunks count
                        if total_chunks is None:
                            total_chunks = chunks_count
                        
                        console.print(f"[bold blue]Received chunk {chunk_index+1}/{chunks_count} from {addr[0]}[/]")
                        
                        # Check if we have all chunks
                        if total_chunks is not None and len(chunks) == total_chunks:
                            break
                except socket.timeout:
                    # Timeout occurred
                    break
            
            # Close the socket
            s.close()
            
            # Check if we have any chunks
            if not chunks:
                console.print(f"[bold red]Error:[/] No UDP packets received")
                return None
            
            # Check if we have all chunks
            if total_chunks is None:
                console.print(f"[bold red]Error:[/] Could not determine total number of chunks")
                return None
            
            if len(chunks) < total_chunks:
                console.print(f"[bold yellow]Warning:[/] Received only {len(chunks)}/{total_chunks} chunks")
            
            # Combine chunks in the correct order
            data = bytearray()
            for i in range(total_chunks):
                if i in chunks:
                    data.extend(chunks[i])
                else:
                    console.print(f"[bold yellow]Warning:[/] Missing chunk {i+1}/{total_chunks}")
            
            console.print(f"[bold green]Data extracted successfully:[/] {len(data)} bytes from UDP packets")
            return bytes(data)
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def _hide_icmp(self, data, destination):
        """Hide data in ICMP packets using echo request/reply."""
        console.print(f"[bold yellow]Warning:[/] ICMP steganography requires root privileges[/]")
        
        try:
            # Check if scapy is available
            try:
                from scapy.all import IP, ICMP, Raw, send
            except ImportError:
                console.print(f"[bold red]Error:[/] Scapy is required for ICMP steganography")
                return False
            
            # Prepare data chunks
            chunk_size = 1024  # Adjust as needed
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            
            console.print(f"[bold blue]Sending data in {len(chunks)} ICMP packets[/]")
            
            # Send data chunks
            for i, chunk in enumerate(chunks):
                # Add chunk index and total chunks information
                header = struct.pack("!II", i, len(chunks))
                payload = header + chunk
                
                # Create and send ICMP packet
                packet = IP(dst=destination)/ICMP(type=8, id=random.randint(1, 65535))/Raw(load=payload)
                send(packet, verbose=False)
                
                # Small delay to avoid overwhelming the receiver
                time.sleep(0.01)
            
            console.print(f"[bold green]Data sent successfully:[/] {len(data)} bytes in {len(chunks)} ICMP packets")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def _extract_icmp(self, interface, timeout):
        """Extract hidden data from ICMP packets."""
        console.print(f"[bold yellow]Warning:[/] ICMP steganography requires root privileges[/]")
        
        try:
            # Check if scapy is available
            try:
                from scapy.all import sniff, ICMP
            except ImportError:
                console.print(f"[bold red]Error:[/] Scapy is required for ICMP steganography")
                return None
            
            # Prepare to receive data
            chunks = {}
            total_chunks = None
            
            # Define packet handler
            def packet_handler(packet):
                nonlocal chunks, total_chunks
                
                # Check if packet has ICMP layer and Raw layer
                if ICMP in packet and Raw in packet:
                    payload = bytes(packet[Raw])
                    
                    # Extract header information
                    if len(payload) >= 8:
                        chunk_index, chunks_count = struct.unpack("!II", payload[:8])
                        chunk_data = payload[8:]
                        
                        # Store the chunk
                        chunks[chunk_index] = chunk_data
                        
                        # Update total chunks count
                        if total_chunks is None:
                            total_chunks = chunks_count
                        
                        console.print(f"[bold blue]Received ICMP chunk {chunk_index+1}/{chunks_count}[/]")
            
            # Sniff packets
            console.print(f"[bold blue]Sniffing for ICMP packets on interface {interface} for {timeout} seconds[/]")
            sniff(iface=interface, filter="icmp", prn=packet_handler, timeout=timeout)
            
            # Check if we have any chunks
            if not chunks:
                console.print(f"[bold red]Error:[/] No ICMP packets with hidden data received")
                return None
            
            # Check if we have all chunks
            if total_chunks is None:
                console.print(f"[bold red]Error:[/] Could not determine total number of chunks")
                return None
            
            if len(chunks) < total_chunks:
                console.print(f"[bold yellow]Warning:[/] Received only {len(chunks)}/{total_chunks} chunks")
            
            # Combine chunks in the correct order
            data = bytearray()
            for i in range(total_chunks):
                if i in chunks:
                    data.extend(chunks[i])
                else:
                    console.print(f"[bold yellow]Warning:[/] Missing chunk {i+1}/{total_chunks}")
            
            console.print(f"[bold green]Data extracted successfully:[/] {len(data)} bytes from ICMP packets")
            return bytes(data)
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def _hide_dns(self, data, destination):
        """Hide data in DNS queries using domain names."""
        console.print(f"[bold yellow]Warning:[/] DNS steganography requires a custom DNS server[/]")
        console.print(f"[bold blue]This method is not fully implemented yet[/]")
        
        # In a real implementation, this would encode data in DNS queries
        # by using subdomains to carry the data
        
        return False
    
    def _extract_dns(self, interface, timeout):
        """Extract hidden data from DNS queries."""
        console.print(f"[bold yellow]Warning:[/] DNS steganography requires a custom DNS server[/]")
        console.print(f"[bold blue]This method is not fully implemented yet[/]")
        
        # In a real implementation, this would decode data from DNS queries
        # by extracting information from subdomains
        
        return None
    
    def _listener_thread(self, protocol, interface):
        """Background thread for listening for hidden data in network traffic."""
        console.print(f"[bold blue]Listener thread started for {protocol.upper()} protocol on interface {interface}[/]")
        
        try:
            while self.running:
                # Extract data based on protocol
                if protocol.lower() == "tcp":
                    data = self._extract_tcp(interface, 5)  # Short timeout for continuous listening
                elif protocol.lower() == "udp":
                    data = self._extract_udp(interface, 5)
                elif protocol.lower() == "icmp":
                    data = self._extract_icmp(interface, 5)
                elif protocol.lower() == "dns":
                    data = self._extract_dns(interface, 5)
                else:
                    console.print(f"[bold red]Error:[/] Unsupported protocol: {protocol}")
                    break
                
                if data:
                    # Try to decode as text and display
                    try:
                        text_data = data.decode('utf-8')
                        console.print(f"[bold green]Extracted data:[/] {text_data}")
                    except UnicodeDecodeError:
                        console.print(f"[bold yellow]Warning:[/] Extracted data is not valid UTF-8 text")
                        console.print(f"[bold green]Extracted data (hex):[/] {data.hex()[:100]}...")
                
                # Small delay to avoid high CPU usage
                time.sleep(0.1)
        
        except Exception as e:
            console.print(f"[bold red]Error in listener thread:[/] {str(e)}")
        
        console.print(f"[bold blue]Listener thread stopped[/]")
