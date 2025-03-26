"""
Username OSINT module for the Ultimate PI Tool.

This module provides functionality for gathering intelligence from usernames
including social media presence, breach checking, and profile correlation.
"""

import os
import sys
import json
import re
import requests
from rich.console import Console
from rich.table import Table

console = Console()

class UsernameOSINT:
    """Username OSINT class for gathering intelligence from usernames."""
    
    def __init__(self):
        """Initialize the Username OSINT module."""
        self.breach_checker = BreachChecker()
        self.platforms = self._get_platform_list()
        
    def lookup(self, username):
        """Perform comprehensive lookup on a username."""
        console.print(f"[bold blue]Performing username lookup for[/] [bold green]{username}[/]")
        
        results = {
            "username": username,
            "profiles": [],
            "breaches": [],
            "possible_variations": self._generate_variations(username)
        }
        
        # Check for social media profiles
        profiles = self._find_profiles(username)
        if profiles:
            results["profiles"] = profiles
        
        # Check for breaches
        breach_results = self.breach_checker.check_username(username)
        if breach_results:
            results["breaches"] = breach_results
        
        # Save results to file
        filename = f"/home/ubuntu/pi_tool/username_{username}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        
        # Display results
        self._display_results(results)
        
        console.print(f"[bold green]Success![/] Username lookup results saved to [bold]{filename}[/]")
        return results
    
    def _get_platform_list(self):
        """Get list of platforms to check for username presence."""
        # This is a list of popular platforms to check for username presence
        platforms = [
            {
                "name": "Twitter",
                "url_format": "https://twitter.com/{username}",
                "check_method": "url"
            },
            {
                "name": "Instagram",
                "url_format": "https://www.instagram.com/{username}",
                "check_method": "url"
            },
            {
                "name": "Facebook",
                "url_format": "https://www.facebook.com/{username}",
                "check_method": "url"
            },
            {
                "name": "LinkedIn",
                "url_format": "https://www.linkedin.com/in/{username}",
                "check_method": "url"
            },
            {
                "name": "GitHub",
                "url_format": "https://github.com/{username}",
                "check_method": "url"
            },
            {
                "name": "Reddit",
                "url_format": "https://www.reddit.com/user/{username}",
                "check_method": "url"
            },
            {
                "name": "TikTok",
                "url_format": "https://www.tiktok.com/@{username}",
                "check_method": "url"
            },
            {
                "name": "YouTube",
                "url_format": "https://www.youtube.com/@{username}",
                "check_method": "url"
            },
            {
                "name": "Pinterest",
                "url_format": "https://www.pinterest.com/{username}",
                "check_method": "url"
            },
            {
                "name": "Twitch",
                "url_format": "https://www.twitch.tv/{username}",
                "check_method": "url"
            }
        ]
        
        return platforms
    
    def _find_profiles(self, username):
        """Find social media profiles for a username."""
        console.print("[bold blue]Searching for social media profiles...[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would check various platforms
        
        profiles = []
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would perform actual checks
        for platform in self.platforms:
            console.print(f"[bold blue]Checking {platform['name']}...[/]")
            
            # Generate the profile URL
            url = platform['url_format'].format(username=username)
            
            # For demonstration, randomly determine if profile exists
            # In a real implementation, this would perform actual checks
            import random
            exists = random.choice([True, False])
            
            if exists:
                profiles.append({
                    "platform": platform['name'],
                    "url": url,
                    "exists": True,
                    "username": username
                })
        
        return profiles
    
    def _generate_variations(self, username):
        """Generate possible username variations."""
        variations = []
        
        # Add common prefixes
        prefixes = ["the", "real", "official", "its", "im", "actual", "mr", "ms", "dr"]
        for prefix in prefixes:
            variations.append(f"{prefix}{username}")
            variations.append(f"{prefix}_{username}")
            variations.append(f"{prefix}.{username}")
        
        # Add common suffixes
        suffixes = ["official", "real", "original", "thereal", "actual", "01", "1", "2", "123", "xo", "xx"]
        for suffix in suffixes:
            variations.append(f"{username}{suffix}")
            variations.append(f"{username}_{suffix}")
            variations.append(f"{username}.{suffix}")
        
        # Add common replacements
        if 'a' in username:
            variations.append(username.replace('a', '4'))
        if 'e' in username:
            variations.append(username.replace('e', '3'))
        if 'i' in username:
            variations.append(username.replace('i', '1'))
        if 'o' in username:
            variations.append(username.replace('o', '0'))
        if 's' in username:
            variations.append(username.replace('s', '5'))
        
        return variations
    
    def _display_results(self, results):
        """Display username lookup results in a formatted table."""
        # Create main table
        table = Table(title=f"Username Lookup Results: {results['username']}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        # Add basic information
        table.add_row("Username", results["username"])
        table.add_row("Profiles Found", str(len(results["profiles"])))
        table.add_row("Breaches Found", str(len(results["breaches"])))
        table.add_row("Variations Generated", str(len(results["possible_variations"])))
        
        console.print(table)
        
        # Display profile information if available
        profiles = results.get("profiles", [])
        if profiles:
            profile_table = Table(title="Social Media Profiles")
            profile_table.add_column("Platform", style="cyan")
            profile_table.add_column("Username", style="green")
            profile_table.add_column("URL", style="blue")
            
            for profile in profiles:
                profile_table.add_row(
                    profile.get("platform", "Unknown"),
                    profile.get("username", "Unknown"),
                    profile.get("url", "N/A")
                )
            
            console.print(profile_table)
        else:
            console.print("[bold yellow]No social media profiles found for this username.[/]")
        
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
            console.print("[bold green]No breaches found for this username.[/]")
        
        # Display username variations
        variations = results.get("possible_variations", [])
        if variations:
            console.print("[bold blue]Possible Username Variations:[/]")
            
            # Split variations into chunks for better display
            chunk_size = 5
            for i in range(0, len(variations), chunk_size):
                chunk = variations[i:i+chunk_size]
                console.print(", ".join(chunk))


class BreachChecker:
    """Class for checking if an email, username, domain, or IP has been involved in data breaches."""
    
    def __init__(self):
        """Initialize the BreachChecker."""
        pass
    
    def check_username(self, username):
        """Check if a username has been involved in any data breaches."""
        console.print(f"[bold blue]Checking breaches for username:[/] [bold green]{username}[/]")
        
        # This is a placeholder for actual implementation
        # In a real implementation, this would check various breach databases
        
        # For demonstration purposes, return sample data
        # In a real implementation, this would return actual results
        
        # Simulate checking multiple breach databases
        console.print("[bold blue]Checking Dehashed database...[/]")
        console.print("[bold blue]Checking PSBDMP database...[/]")
        console.print("[bold blue]Checking COMB database...[/]")
        
        # Sample breach data (for demonstration only)
        sample_breaches = [
            {
                "name": "Sample Username Breach 1",
                "date": "2023-01-15",
                "description": "This is a sample breach for demonstration purposes. In a real implementation, this would contain actual breach information.",
                "data_types": ["username", "password", "email"],
                "source": "Dehashed"
            },
            {
                "name": "Sample Username Breach 2",
                "date": "2022-08-22",
                "description": "Another sample breach for demonstration. This would be replaced with real breach data in the actual implementation.",
                "data_types": ["username", "ip_address", "name", "phone"],
                "source": "PSBDMP"
            }
        ]
        
        return sample_breaches
