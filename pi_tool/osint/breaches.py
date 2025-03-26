"""
Breaches OSINT module for the Ultimate PI Tool.

This module provides functionality for checking if emails, usernames, domains, 
or IP addresses have been involved in data breaches.
"""

import os
import sys
import json
import requests
from rich.console import Console
from rich.table import Table

console = Console()

class BreachOSINT:
    """Breach OSINT class for checking data breaches."""
    
    def __init__(self):
        """Initialize the Breach OSINT module."""
        self.breach_checker = BreachChecker()
        
    def check_email(self, email):
        """Check if an email has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for email:[/] [bold green]{email}[/]")
        
        results = {
            "email": email,
            "breaches": [],
            "breach_count": 0,
            "exposed_data_types": set()
        }
        
        # Check for breaches
        breach_results = self.breach_checker.check_email(email)
        if breach_results:
            results["breaches"] = breach_results
            results["breach_count"] = len(breach_results)
            
            # Collect all exposed data types
            for breach in breach_results:
                data_types = breach.get("data_types", [])
                for data_type in data_types:
                    results["exposed_data_types"].add(data_type)
            
            # Convert set to list for JSON serialization
            results["exposed_data_types"] = list(results["exposed_data_types"])
        
        # Save results to file
        filename = f"/home/ubuntu/pi_tool/breach_email_{email.replace('@', '_at_')}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        
        # Display results
        self._display_results(results, "Email")
        
        console.print(f"[bold green]Success![/] Breach check results saved to [bold]{filename}[/]")
        return results
    
    def check_username(self, username):
        """Check if a username has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for username:[/] [bold green]{username}[/]")
        
        results = {
            "username": username,
            "breaches": [],
            "breach_count": 0,
            "exposed_data_types": set()
        }
        
        # Check for breaches
        breach_results = self.breach_checker.check_username(username)
        if breach_results:
            results["breaches"] = breach_results
            results["breach_count"] = len(breach_results)
            
            # Collect all exposed data types
            for breach in breach_results:
                data_types = breach.get("data_types", [])
                for data_type in data_types:
                    results["exposed_data_types"].add(data_type)
            
            # Convert set to list for JSON serialization
            results["exposed_data_types"] = list(results["exposed_data_types"])
        
        # Save results to file
        filename = f"/home/ubuntu/pi_tool/breach_username_{username}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        
        # Display results
        self._display_results(results, "Username")
        
        console.print(f"[bold green]Success![/] Breach check results saved to [bold]{filename}[/]")
        return results
    
    def check_domain(self, domain):
        """Check if a domain has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for domain:[/] [bold green]{domain}[/]")
        
        results = {
            "domain": domain,
            "breaches": [],
            "breach_count": 0,
            "exposed_data_types": set()
        }
        
        # Check for breaches
        breach_results = self.breach_checker.check_domain(domain)
        if breach_results:
            results["breaches"] = breach_results
            results["breach_count"] = len(breach_results)
            
            # Collect all exposed data types
            for breach in breach_results:
                data_types = breach.get("data_types", [])
                for data_type in data_types:
                    results["exposed_data_types"].add(data_type)
            
            # Convert set to list for JSON serialization
            results["exposed_data_types"] = list(results["exposed_data_types"])
        
        # Save results to file
        filename = f"/home/ubuntu/pi_tool/breach_domain_{domain.replace('.', '_')}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        
        # Display results
        self._display_results(results, "Domain")
        
        console.print(f"[bold green]Success![/] Breach check results saved to [bold]{filename}[/]")
        return results
    
    def check_ip(self, ip_address):
        """Check if an IP address has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for IP address:[/] [bold green]{ip_address}[/]")
        
        results = {
            "ip_address": ip_address,
            "breaches": [],
            "breach_count": 0,
            "exposed_data_types": set()
        }
        
        # Check for breaches
        breach_results = self.breach_checker.check_ip(ip_address)
        if breach_results:
            results["breaches"] = breach_results
            results["breach_count"] = len(breach_results)
            
            # Collect all exposed data types
            for breach in breach_results:
                data_types = breach.get("data_types", [])
                for data_type in data_types:
                    results["exposed_data_types"].add(data_type)
            
            # Convert set to list for JSON serialization
            results["exposed_data_types"] = list(results["exposed_data_types"])
        
        # Save results to file
        filename = f"/home/ubuntu/pi_tool/breach_ip_{ip_address.replace('.', '_')}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        
        # Display results
        self._display_results(results, "IP Address")
        
        console.print(f"[bold green]Success![/] Breach check results saved to [bold]{filename}[/]")
        return results
    
    def _display_results(self, results, entity_type):
        """Display breach check results in a formatted table."""
        # Create main table
        entity_value = results.get(entity_type.lower().replace(" ", "_"), "Unknown")
        table = Table(title=f"Breach Check Results: {entity_type} - {entity_value}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        # Add basic information
        table.add_row(entity_type, entity_value)
        table.add_row("Breaches Found", str(results.get("breach_count", 0)))
        
        # Add exposed data types if available
        exposed_types = results.get("exposed_data_types", [])
        if exposed_types:
            table.add_row("Exposed Data Types", ", ".join(exposed_types))
        
        console.print(table)
        
        # Display breach information if available
        breaches = results.get("breaches", [])
        if breaches:
            breach_table = Table(title="Data Breach Information")
            breach_table.add_column("Breach Name", style="red")
            breach_table.add_column("Date", style="yellow")
            breach_table.add_column("Source", style="blue")
            breach_table.add_column("Description", style="green")
            
            for breach in breaches:
                breach_table.add_row(
                    breach.get("name", "Unknown"),
                    breach.get("date", "Unknown"),
                    breach.get("source", "Unknown"),
                    breach.get("description", "No description available")[:100] + "..."
                )
            
            console.print(breach_table)
        else:
            console.print(f"[bold green]No breaches found for this {entity_type.lower()}.[/]")


class BreachChecker:
    """Class for checking if an email, username, domain, or IP has been involved in data breaches."""
    
    def __init__(self):
        """Initialize the BreachChecker."""
        # Initialize breach databases
        self.databases = [
            {"name": "Dehashed", "description": "A paid search engine for database breaches and credentials"},
            {"name": "HaveIBeenPwned", "description": "A free service that aggregates data breaches"},
            {"name": "IntelX", "description": "Intelligence X search engine for leaked data"},
            {"name": "PSBDMP", "description": "Pastebin dump search engine"},
            {"name": "COMB", "description": "Compilation of Many Breaches dataset"},
            {"name": "Spycloud", "description": "Breach monitoring and alerting service"},
            {"name": "HudsonRock", "description": "Cybercrime intelligence platform"},
            {"name": "CyberNews", "description": "Cybersecurity news and breach monitoring service"}
        ]
    
    def check_email(self, email):
        """Check if an email has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for email:[/] [bold green]{email}[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would check various breach databases
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would return actual results
        
        # Simulate checking multiple breach databases
        for db in self.databases:
            console.print(f"[bold blue]Checking {db['name']} database...[/]")
        
        # Sample breach data (for demonstration only)
        sample_breaches = [
            {
                "name": "Sample Email Breach 1",
                "date": "2023-01-15",
                "description": "This is a sample breach for demonstration purposes. In a real implementation, this would contain actual breach information.",
                "data_types": ["email", "password", "username"],
                "source": "Dehashed"
            },
            {
                "name": "Sample Email Breach 2",
                "date": "2022-08-22",
                "description": "Another sample breach for demonstration. This would be replaced with real breach data in the actual implementation.",
                "data_types": ["email", "ip_address", "name", "phone"],
                "source": "HaveIBeenPwned"
            },
            {
                "name": "Sample Email Breach 3",
                "date": "2021-11-05",
                "description": "A third sample breach for demonstration. This would be replaced with real breach data in the actual implementation.",
                "data_types": ["email", "password", "address", "credit_card"],
                "source": "COMB"
            }
        ]
        
        return sample_breaches
    
    def check_username(self, username):
        """Check if a username has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for username:[/] [bold green]{username}[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would check various breach databases
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would return actual results
        
        # Simulate checking multiple breach databases
        for db in self.databases[:3]:  # Check fewer databases for username
            console.print(f"[bold blue]Checking {db['name']} database...[/]")
        
        # Sample breach data (for demonstration only)
        sample_breaches = [
            {
                "name": "Sample Username Breach 1",
                "date": "2023-02-18",
                "description": "This is a sample breach for demonstration purposes. In a real implementation, this would contain actual breach information.",
                "data_types": ["username", "password", "email"],
                "source": "Dehashed"
            },
            {
                "name": "Sample Username Breach 2",
                "date": "2022-05-10",
                "description": "Another sample breach for demonstration. This would be replaced with real breach data in the actual implementation.",
                "data_types": ["username", "ip_address", "name", "phone"],
                "source": "PSBDMP"
            }
        ]
        
        return sample_breaches
    
    def check_domain(self, domain):
        """Check if a domain has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for domain:[/] [bold green]{domain}[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would check various breach databases
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would return actual results
        
        # Simulate checking multiple breach databases
        for db in self.databases[:4]:  # Check fewer databases for domain
            console.print(f"[bold blue]Checking {db['name']} database...[/]")
        
        # Sample breach data (for demonstration only)
        sample_breaches = [
            {
                "name": "Sample Domain Breach 1",
                "date": "2022-11-30",
                "description": "This is a sample breach for demonstration purposes. In a real implementation, this would contain actual breach information.",
                "data_types": ["email", "domain", "password"],
                "source": "IntelX"
            },
            {
                "name": "Sample Domain Breach 2",
                "date": "2021-07-14",
                "description": "Another sample breach for demonstration. This would be replaced with real breach data in the actual implementation.",
                "data_types": ["domain", "ip_address", "email", "username"],
                "source": "HaveIBeenPwned"
            }
        ]
        
        return sample_breaches
    
    def check_ip(self, ip_address):
        """Check if an IP address has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for IP address:[/] [bold green]{ip_address}[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would check various breach databases
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would return actual results
        
        # Simulate checking multiple breach databases
        for db in self.databases[:3]:  # Check fewer databases for IP
            console.print(f"[bold blue]Checking {db['name']} database...[/]")
        
        # Sample breach data (for demonstration only)
        sample_breaches = [
            {
                "name": "Sample IP Breach 1",
                "date": "2023-02-18",
                "description": "This is a sample breach for demonstration purposes. In a real implementation, this would contain actual breach information.",
                "data_types": ["ip_address", "username", "email"],
                "source": "PSBDMP"
            },
            {
                "name": "Sample IP Breach 2",
                "date": "2022-09-05",
                "description": "Another sample breach for demonstration. This would be replaced with real breach data in the actual implementation.",
                "data_types": ["ip_address", "geolocation", "username"],
                "source": "IntelX"
            }
        ]
        
        return sample_breaches
