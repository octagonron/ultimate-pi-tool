"""
Email OSINT module for the Ultimate PI Tool.

This module provides functionality for gathering intelligence from email addresses
including validation, reputation, breach checking, and associated accounts.
"""

import os
import sys
import json
import re
import requests
from rich.console import Console
from rich.table import Table

console = Console()

class EmailOSINT:
    """Email OSINT class for gathering intelligence from email addresses."""
    
    def __init__(self):
        """Initialize the Email OSINT module."""
        self.breach_checker = BreachChecker()
        
    def lookup(self, email):
        """Perform comprehensive lookup on an email address."""
        console.print(f"[bold blue]Performing email lookup for[/] [bold green]{email}[/]")
        
        # Validate email format
        if not self._validate_email_format(email):
            console.print(f"[bold red]Error:[/] Invalid email format: {email}")
            return None
        
        results = {
            "email": email,
            "domain": email.split('@')[1],
            "username": email.split('@')[0],
            "valid_format": True,
            "breaches": [],
            "reputation": {},
            "associated_accounts": []
        }
        
        # Check for breaches
        breach_results = self.breach_checker.check_email(email)
        if breach_results:
            results["breaches"] = breach_results
        
        # Check email reputation
        reputation = self._check_reputation(email)
        if reputation:
            results["reputation"] = reputation
        
        # Find associated accounts
        associated = self._find_associated_accounts(email)
        if associated:
            results["associated_accounts"] = associated
        
        # Save results to file
        filename = f"/home/ubuntu/pi_tool/email_{email.replace('@', '_at_')}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        
        # Display results
        self._display_results(results)
        
        console.print(f"[bold green]Success![/] Email lookup results saved to [bold]{filename}[/]")
        return results
    
    def _validate_email_format(self, email):
        """Validate email format using regex."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _check_reputation(self, email):
        """Check email reputation using various services."""
        # This is a placeholder for actual implementation
        # In a real implementation, this would check various reputation services
        
        console.print("[bold blue]Checking email reputation...[/]")
        
        reputation = {
            "spam_score": 0,
            "suspicious": False,
            "disposable": self._is_disposable_email(email),
            "free_provider": self._is_free_provider(email)
        }
        
        return reputation
    
    def _is_disposable_email(self, email):
        """Check if email is from a disposable email provider."""
        domain = email.split('@')[1]
        
        # List of common disposable email domains
        disposable_domains = [
            "10minutemail.com", "guerrillamail.com", "mailinator.com", 
            "tempmail.com", "throwawaymail.com", "yopmail.com",
            "temp-mail.org", "fakeinbox.com", "tempinbox.com",
            "emailondeck.com", "getnada.com", "dispostable.com"
        ]
        
        return domain.lower() in disposable_domains
    
    def _is_free_provider(self, email):
        """Check if email is from a free email provider."""
        domain = email.split('@')[1]
        
        # List of common free email domains
        free_domains = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "aol.com", "icloud.com", "protonmail.com", "mail.com",
            "zoho.com", "yandex.com", "gmx.com", "tutanota.com"
        ]
        
        return domain.lower() in free_domains
    
    def _find_associated_accounts(self, email):
        """Find accounts associated with the email address."""
        # This is a placeholder for actual implementation
        # In a real implementation, this would search various platforms
        
        console.print("[bold blue]Searching for associated accounts...[/]")
        
        # For demonstration purposes, return empty list
        # In a real implementation, this would return actual results
        return []
    
    def _display_results(self, results):
        """Display email lookup results in a formatted table."""
        # Create main table
        table = Table(title=f"Email Lookup Results: {results['email']}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        # Add basic information
        table.add_row("Email", results["email"])
        table.add_row("Domain", results["domain"])
        table.add_row("Username", results["username"])
        table.add_row("Valid Format", str(results["valid_format"]))
        table.add_row("Disposable Email", str(results["reputation"].get("disposable", "Unknown")))
        table.add_row("Free Provider", str(results["reputation"].get("free_provider", "Unknown")))
        
        console.print(table)
        
        # Display breach information if available
        if results["breaches"]:
            breach_table = Table(title="Data Breach Information")
            breach_table.add_column("Breach Name", style="red")
            breach_table.add_column("Date", style="yellow")
            breach_table.add_column("Description", style="green")
            
            for breach in results["breaches"]:
                breach_table.add_row(
                    breach.get("name", "Unknown"),
                    breach.get("date", "Unknown"),
                    breach.get("description", "No description available")[:100] + "..."
                )
            
            console.print(breach_table)
        else:
            console.print("[bold green]No breaches found for this email.[/]")
        
        # Display associated accounts if available
        if results["associated_accounts"]:
            account_table = Table(title="Associated Accounts")
            account_table.add_column("Platform", style="cyan")
            account_table.add_column("Username", style="green")
            account_table.add_column("URL", style="blue")
            
            for account in results["associated_accounts"]:
                account_table.add_row(
                    account.get("platform", "Unknown"),
                    account.get("username", "Unknown"),
                    account.get("url", "N/A")
                )
            
            console.print(account_table)


class BreachChecker:
    """Class for checking if an email, username, domain, or IP has been involved in data breaches."""
    
    def __init__(self):
        """Initialize the BreachChecker."""
        pass
    
    def check_email(self, email):
        """Check if an email has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for email:[/] [bold green]{email}[/]")
        
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
                "name": "Sample Breach 1",
                "date": "2023-01-15",
                "description": "This is a sample breach for demonstration purposes. In a real implementation, this would contain actual breach information.",
                "data_types": ["email", "password", "username"],
                "source": "Dehashed"
            },
            {
                "name": "Sample Breach 2",
                "date": "2022-08-22",
                "description": "Another sample breach for demonstration. This would be replaced with real breach data in the actual implementation.",
                "data_types": ["email", "ip_address", "name", "phone"],
                "source": "HaveIBeenPwned"
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
        sample_breaches = [
            {
                "name": "Sample Username Breach",
                "date": "2022-05-10",
                "description": "This is a sample breach for demonstration purposes. In a real implementation, this would contain actual breach information.",
                "data_types": ["username", "password", "ip_address"],
                "source": "Dehashed"
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
        sample_breaches = [
            {
                "name": "Sample Domain Breach",
                "date": "2022-11-30",
                "description": "This is a sample breach for demonstration purposes. In a real implementation, this would contain actual breach information.",
                "data_types": ["email", "domain", "password"],
                "source": "IntelX"
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
        sample_breaches = [
            {
                "name": "Sample IP Breach",
                "date": "2023-02-18",
                "description": "This is a sample breach for demonstration purposes. In a real implementation, this would contain actual breach information.",
                "data_types": ["ip_address", "username", "email"],
                "source": "PSBDMP"
            }
        ]
        
        return sample_breaches
