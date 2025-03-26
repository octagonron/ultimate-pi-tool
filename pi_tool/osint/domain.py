"""
Domain OSINT module for the Ultimate PI Tool.

This module provides functionality for gathering intelligence from domains
including WHOIS information, DNS records, hosting details, and breach checking.
"""

import os
import sys
import json
import socket
import datetime
from rich.console import Console
from rich.table import Table

console = Console()

class DomainOSINT:
    """Domain OSINT class for gathering intelligence from domains."""
    
    def __init__(self):
        """Initialize the Domain OSINT module."""
        self.breach_checker = BreachChecker()
        
    def lookup(self, domain):
        """Perform comprehensive lookup on a domain."""
        console.print(f"[bold blue]Performing domain lookup for[/] [bold green]{domain}[/]")
        
        results = {
            "domain": domain,
            "whois": {},
            "dns_records": {},
            "ip_addresses": [],
            "hosting_info": {},
            "breaches": [],
            "subdomains": []
        }
        
        # Get WHOIS information
        whois_info = self._get_whois(domain)
        if whois_info:
            results["whois"] = whois_info
        
        # Get DNS records
        dns_records = self._get_dns_records(domain)
        if dns_records:
            results["dns_records"] = dns_records
        
        # Get IP addresses
        ip_addresses = self._get_ip_addresses(domain)
        if ip_addresses:
            results["ip_addresses"] = ip_addresses
        
        # Get hosting information
        hosting_info = self._get_hosting_info(domain)
        if hosting_info:
            results["hosting_info"] = hosting_info
        
        # Check for breaches
        breach_results = self.breach_checker.check_domain(domain)
        if breach_results:
            results["breaches"] = breach_results
        
        # Find subdomains
        subdomains = self._find_subdomains(domain)
        if subdomains:
            results["subdomains"] = subdomains
        
        # Save results to file
        filename = f"/home/ubuntu/pi_tool/domain_{domain.replace('.', '_')}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        
        # Display results
        self._display_results(results)
        
        console.print(f"[bold green]Success![/] Domain lookup results saved to [bold]{filename}[/]")
        return results
    
    def _get_whois(self, domain):
        """Get WHOIS information for a domain."""
        console.print("[bold blue]Retrieving WHOIS information...[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would use a WHOIS library or API
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would return actual results
        sample_whois = {
            "registrar": "Sample Registrar, Inc.",
            "creation_date": str(datetime.datetime.now() - datetime.timedelta(days=365*3)),
            "expiration_date": str(datetime.datetime.now() + datetime.timedelta(days=365*2)),
            "updated_date": str(datetime.datetime.now() - datetime.timedelta(days=30)),
            "status": ["clientTransferProhibited"],
            "name_servers": ["ns1.sampleserver.com", "ns2.sampleserver.com"],
            "registrant": {
                "organization": "Sample Organization",
                "country": "US"
            },
            "admin": {
                "organization": "Sample Organization",
                "country": "US"
            },
            "tech": {
                "organization": "Sample Organization",
                "country": "US"
            }
        }
        
        return sample_whois
    
    def _get_dns_records(self, domain):
        """Get DNS records for a domain."""
        console.print("[bold blue]Retrieving DNS records...[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would use a DNS library or API
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would return actual results
        sample_dns = {
            "A": ["192.0.2.1", "192.0.2.2"],
            "AAAA": ["2001:db8::1"],
            "MX": ["10 mail.example.com", "20 mail2.example.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 include:_spf.example.com ~all"],
            "CNAME": [],
            "SOA": ["ns1.example.com. hostmaster.example.com. 2023010101 3600 1800 604800 86400"]
        }
        
        return sample_dns
    
    def _get_ip_addresses(self, domain):
        """Get IP addresses associated with a domain."""
        console.print("[bold blue]Resolving IP addresses...[/]")
        
        ip_addresses = []
        
        try:
            # Try to resolve the domain to an IPv4 address
            ipv4 = socket.gethostbyname(domain)
            ip_addresses.append({"type": "IPv4", "address": ipv4})
        except:
            console.print("[bold yellow]Warning:[/] Could not resolve IPv4 address")
        
        # For demonstration purposes, add a sample IPv6 address
        # In a real implementation, this would use proper IPv6 resolution
        ip_addresses.append({"type": "IPv6", "address": "2001:db8::1"})
        
        return ip_addresses
    
    def _get_hosting_info(self, domain):
        """Get hosting information for a domain."""
        console.print("[bold blue]Retrieving hosting information...[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would use various APIs or services
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would return actual results
        sample_hosting = {
            "provider": "Sample Hosting Provider",
            "country": "United States",
            "asn": "AS12345",
            "organization": "Sample Network Organization",
            "abuse_contact": "abuse@samplehost.com"
        }
        
        return sample_hosting
    
    def _find_subdomains(self, domain):
        """Find subdomains for a domain."""
        console.print("[bold blue]Searching for subdomains...[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would use various subdomain enumeration techniques
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would return actual results
        sample_subdomains = [
            {"subdomain": f"www.{domain}", "ip": "192.0.2.1"},
            {"subdomain": f"mail.{domain}", "ip": "192.0.2.2"},
            {"subdomain": f"blog.{domain}", "ip": "192.0.2.3"},
            {"subdomain": f"api.{domain}", "ip": "192.0.2.4"},
            {"subdomain": f"dev.{domain}", "ip": "192.0.2.5"}
        ]
        
        return sample_subdomains
    
    def _display_results(self, results):
        """Display domain lookup results in a formatted table."""
        # Create main table
        table = Table(title=f"Domain Lookup Results: {results['domain']}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        # Add WHOIS information
        whois = results.get("whois", {})
        if whois:
            table.add_row("Registrar", whois.get("registrar", "Unknown"))
            table.add_row("Creation Date", whois.get("creation_date", "Unknown"))
            table.add_row("Expiration Date", whois.get("expiration_date", "Unknown"))
            table.add_row("Updated Date", whois.get("updated_date", "Unknown"))
            
            # Add name servers
            name_servers = whois.get("name_servers", [])
            if name_servers:
                table.add_row("Name Servers", ", ".join(name_servers))
        
        # Add IP addresses
        ip_addresses = results.get("ip_addresses", [])
        if ip_addresses:
            ips = []
            for ip in ip_addresses:
                ips.append(f"{ip.get('type', 'IP')}: {ip.get('address', 'Unknown')}")
            table.add_row("IP Addresses", "\n".join(ips))
        
        # Add hosting information
        hosting = results.get("hosting_info", {})
        if hosting:
            table.add_row("Hosting Provider", hosting.get("provider", "Unknown"))
            table.add_row("Hosting Country", hosting.get("country", "Unknown"))
            table.add_row("ASN", hosting.get("asn", "Unknown"))
        
        console.print(table)
        
        # Display DNS records if available
        dns = results.get("dns_records", {})
        if dns:
            dns_table = Table(title="DNS Records")
            dns_table.add_column("Type", style="cyan")
            dns_table.add_column("Records", style="green")
            
            for record_type, records in dns.items():
                if records:
                    dns_table.add_row(record_type, "\n".join(records))
            
            console.print(dns_table)
        
        # Display subdomains if available
        subdomains = results.get("subdomains", [])
        if subdomains:
            subdomain_table = Table(title="Subdomains")
            subdomain_table.add_column("Subdomain", style="cyan")
            subdomain_table.add_column("IP Address", style="green")
            
            for subdomain in subdomains:
                subdomain_table.add_row(
                    subdomain.get("subdomain", "Unknown"),
                    subdomain.get("ip", "Unknown")
                )
            
            console.print(subdomain_table)
        
        # Display breach information if available
        breaches = results.get("breaches", [])
        if breaches:
            breach_table = Table(title="Data Breach Information")
            breach_table.add_column("Breach Name", style="red")
            breach_table.add_column("Date", style="yellow")
            breach_table.add_column("Description", style="green")
            
            for breach in breaches:
                breach_table.add_row(
                    breach.get("name", "Unknown"),
                    breach.get("date", "Unknown"),
                    breach.get("description", "No description available")[:100] + "..."
                )
            
            console.print(breach_table)
        else:
            console.print("[bold green]No breaches found for this domain.[/]")


class BreachChecker:
    """Class for checking if an email, username, domain, or IP has been involved in data breaches."""
    
    def __init__(self):
        """Initialize the BreachChecker."""
        pass
    
    def check_domain(self, domain):
        """Check if a domain has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for domain:[/] [bold green]{domain}[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would check various breach databases
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would return actual results
        
        # Simulate checking multiple breach databases
        console.print("[bold blue]Checking Dehashed database...[/]")
        console.print("[bold blue]Checking HaveIBeenPwned database...[/]")
        console.print("[bold blue]Checking IntelX database...[/]")
        
        # Sample breach data (for demonstration only)
        sample_breaches = [
            {
                "name": "Sample Domain Breach 1",
                "date": "2023-01-15",
                "description": "This is a sample breach for demonstration purposes. In a real implementation, this would contain actual breach information.",
                "data_types": ["email", "password", "username"],
                "source": "Dehashed"
            },
            {
                "name": "Sample Domain Breach 2",
                "date": "2022-08-22",
                "description": "Another sample breach for demonstration. This would be replaced with real breach data in the actual implementation.",
                "data_types": ["email", "ip_address", "name", "phone"],
                "source": "HaveIBeenPwned"
            }
        ]
        
        return sample_breaches
