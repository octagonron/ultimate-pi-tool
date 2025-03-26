"""
LinkedIn OSINT module for the Ultimate PI Tool.

This module provides functionality for gathering intelligence from LinkedIn
using the LinkedIn API.
"""

import os
import sys
import json
from rich.console import Console
from rich.table import Table

# Add path for data API access
sys.path.append('/opt/.manus/.sandbox-runtime')
from data_api import ApiClient

console = Console()

class LinkedInOSINT:
    """LinkedIn OSINT class for gathering intelligence from LinkedIn."""
    
    def __init__(self):
        """Initialize the LinkedIn OSINT module."""
        self.client = ApiClient()
        
    def get_profile(self, username):
        """Get LinkedIn profile information for a given username."""
        console.print(f"[bold blue]Fetching LinkedIn profile for[/] [bold green]{username}[/]")
        
        try:
            # Use the LinkedIn API to get profile data
            result = self.client.call_api('LinkedIn/get_user_profile_by_username', 
                                         query={'username': username})
            
            # Save the raw data to a file
            with open(f"/home/ubuntu/pi_tool/linkedin_{username}_raw.json", "w") as f:
                json.dump(result, f, indent=4)
            
            # Display the profile information
            if result.get('success'):
                data = result.get('data', {})
                
                # Create a table for display
                table = Table(title=f"LinkedIn Profile: {username}")
                table.add_column("Field", style="cyan")
                table.add_column("Value", style="green")
                
                # Extract and display basic profile information
                profile_data = self._extract_profile_data(data)
                for field, value in profile_data.items():
                    table.add_row(field, str(value))
                
                console.print(table)
                
                console.print(f"[bold green]Success![/] Full profile data saved to [bold]linkedin_{username}_raw.json[/]")
                return profile_data
            else:
                console.print(f"[bold red]Error:[/] {result.get('message', 'Unknown error')}")
                return None
                
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def search_people(self, keywords, start=0):
        """Search for people on LinkedIn based on keywords."""
        console.print(f"[bold blue]Searching LinkedIn for people matching:[/] [bold green]{keywords}[/]")
        
        try:
            # Use the LinkedIn API to search for people
            result = self.client.call_api('LinkedIn/search_people', 
                                         query={'keywords': keywords, 'start': str(start)})
            
            # Save the raw data to a file
            filename = f"/home/ubuntu/pi_tool/linkedin_search_{keywords.replace(' ', '_')}_raw.json"
            with open(filename, "w") as f:
                json.dump(result, f, indent=4)
            
            # Display the search results
            if result.get('success'):
                data = result.get('data', {})
                items = data.get('items', [])
                total = data.get('total', 0)
                
                console.print(f"[bold green]Found {total} results[/]")
                
                # Create a table for display
                table = Table(title=f"LinkedIn Search Results: {keywords}")
                table.add_column("Name", style="cyan")
                table.add_column("Headline", style="green")
                table.add_column("Location", style="yellow")
                table.add_column("Profile URL", style="blue")
                
                # Add each result to the table
                for item in items:
                    table.add_row(
                        item.get('fullName', 'N/A'),
                        item.get('headline', 'N/A'),
                        item.get('location', 'N/A'),
                        item.get('profileURL', 'N/A')
                    )
                
                console.print(table)
                
                console.print(f"[bold green]Success![/] Full search results saved to [bold]{filename}[/]")
                return items
            else:
                console.print(f"[bold red]Error:[/] {result.get('message', 'Unknown error')}")
                return None
                
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def _extract_profile_data(self, data):
        """Extract relevant profile data from the API response."""
        profile_data = {}
        
        # Extract data from the response
        # This is a simplified version - the actual implementation would be more comprehensive
        
        # Try to extract from post author if available
        if 'post' in data and 'author' in data['post']:
            author = data['post']['author']
            profile_data['Name'] = f"{author.get('firstName', '')} {author.get('lastName', '')}"
            profile_data['Headline'] = author.get('headline', 'N/A')
            profile_data['Username'] = author.get('username', 'N/A')
            profile_data['Profile URL'] = author.get('url', 'N/A')
        
        # Try to extract from comments if available
        elif 'comments' in data and data['comments'] and 'author' in data['comments'][0]:
            author = data['comments'][0]['author']
            profile_data['Name'] = f"{author.get('firstName', '')} {author.get('LastName', '')}"
            profile_data['Title'] = author.get('title', 'N/A')
            profile_data['Username'] = author.get('username', 'N/A')
            profile_data['Profile URL'] = author.get('linkedinUrl', 'N/A')
        
        # If no data was extracted, return a placeholder
        if not profile_data:
            profile_data['Status'] = 'No profile data found'
        
        return profile_data
