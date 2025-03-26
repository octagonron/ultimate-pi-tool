"""
Alias Tracker module for the Ultimate PI Tool.

This module provides functionality for tracking and cross-referencing aliases
across various systems including PACER and property records.
"""

import os
import sys
import re
import json
import requests
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

class AliasTracker:
    """Alias Tracker class for tracking and cross-referencing aliases."""
    
    def __init__(self):
        """Initialize the Alias Tracker module."""
        self.aliases_db = {}
        self.load_aliases_db()
    
    def search_alias(self, name):
        """Search for aliases associated with a name."""
        console.print(f"[bold blue]Searching for aliases associated with:[/] [bold green]{name}[/]")
        
        try:
            # Normalize the name
            normalized_name = self._normalize_name(name)
            
            # Search in local database
            results = self._search_local_db(normalized_name)
            
            # Display results
            if results:
                table = Table(title=f"Aliases for {name}")
                table.add_column("Alias", style="cyan")
                table.add_column("Source", style="green")
                table.add_column("Last Updated", style="yellow")
                table.add_column("Confidence", style="magenta")
                
                for alias in results:
                    table.add_row(
                        alias['alias'],
                        alias['source'],
                        alias['last_updated'],
                        f"{alias['confidence']}%"
                    )
                
                console.print(table)
                
                # Offer to search external sources
                console.print("[bold blue]Would you like to search external sources for additional aliases?[/]")
                console.print("1. Search PACER")
                console.print("2. Search Property Records")
                console.print("3. Search All External Sources")
                console.print("4. Skip External Search")
                
                choice = input("Enter your choice (1-4): ")
                
                if choice == "1":
                    self.search_pacer(name)
                elif choice == "2":
                    location = input("Enter location (city, state, or zip): ")
                    self.search_property_records(name, location)
                elif choice == "3":
                    self.search_pacer(name)
                    location = input("Enter location for property search (city, state, or zip): ")
                    self.search_property_records(name, location)
            else:
                console.print(f"[bold yellow]No aliases found for {name} in local database.[/]")
                console.print("[bold blue]Searching external sources...[/]")
                
                # Search external sources
                self.search_pacer(name)
                location = input("Enter location for property search (city, state, or zip): ")
                self.search_property_records(name, location)
            
            return results
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def track_alias(self, name):
        """Track a name and its aliases over time."""
        console.print(f"[bold blue]Setting up tracking for:[/] [bold green]{name}[/]")
        
        try:
            # Normalize the name
            normalized_name = self._normalize_name(name)
            
            # Check if already tracking
            if normalized_name in self.aliases_db:
                console.print(f"[bold yellow]Already tracking {name}.[/]")
                
                # Display current tracking info
                aliases = self.aliases_db[normalized_name]
                
                table = Table(title=f"Tracking Information for {name}")
                table.add_column("Alias", style="cyan")
                table.add_column("Source", style="green")
                table.add_column("Last Updated", style="yellow")
                table.add_column("Confidence", style="magenta")
                
                for alias in aliases:
                    table.add_row(
                        alias['alias'],
                        alias['source'],
                        alias['last_updated'],
                        f"{alias['confidence']}%"
                    )
                
                console.print(table)
            else:
                # Add to tracking database
                self.aliases_db[normalized_name] = []
                
                # Add the name itself as an alias
                self._add_alias(normalized_name, name, "Initial Entry", 100)
                
                console.print(f"[bold green]Now tracking {name}.[/]")
                
                # Save the database
                self.save_aliases_db()
                
                # Offer to search for initial aliases
                console.print("[bold blue]Would you like to search for initial aliases?[/]")
                console.print("1. Yes")
                console.print("2. No")
                
                choice = input("Enter your choice (1-2): ")
                
                if choice == "1":
                    self.search_alias(name)
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def search_pacer(self, name):
        """Search PACER (Public Access to Court Electronic Records) for a name."""
        console.print(f"[bold blue]Searching PACER for:[/] [bold green]{name}[/]")
        
        try:
            # Normalize the name
            normalized_name = self._normalize_name(name)
            
            # In a real implementation, this would use PACER API or web scraping
            # For demonstration, we'll simulate a PACER search
            console.print("[bold yellow]Note:[/] This is a simulated PACER search. In a real implementation, this would connect to the PACER API.")
            
            with Progress() as progress:
                task = progress.add_task("[cyan]Searching PACER...", total=100)
                
                # Simulate search progress
                for i in range(100):
                    progress.update(task, advance=1)
                    import time
                    time.sleep(0.02)
            
            # Simulate search results
            results = self._simulate_pacer_search(name)
            
            if results:
                # Display results
                table = Table(title=f"PACER Results for {name}")
                table.add_column("Case Number", style="cyan")
                table.add_column("Court", style="green")
                table.add_column("Filing Date", style="yellow")
                table.add_column("Party Name", style="magenta")
                table.add_column("Role", style="blue")
                
                for case in results:
                    table.add_row(
                        case['case_number'],
                        case['court'],
                        case['filing_date'],
                        case['party_name'],
                        case['role']
                    )
                
                console.print(table)
                
                # Extract potential aliases
                aliases = set()
                for case in results:
                    aliases.add(case['party_name'])
                
                # Remove the original name
                if name in aliases:
                    aliases.remove(name)
                
                # Add aliases to tracking database
                if aliases:
                    console.print(f"[bold green]Found {len(aliases)} potential aliases in PACER records.[/]")
                    
                    for alias in aliases:
                        self._add_alias(normalized_name, alias, "PACER", 80)
                    
                    # Save the database
                    self.save_aliases_db()
                else:
                    console.print("[bold yellow]No new aliases found in PACER records.[/]")
            else:
                console.print("[bold yellow]No PACER records found for this name.[/]")
            
            return results
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def search_property_records(self, name, location):
        """Search property records for a name in a specific location."""
        console.print(f"[bold blue]Searching property records for:[/] [bold green]{name}[/] in [bold green]{location}[/]")
        
        try:
            # Normalize the name
            normalized_name = self._normalize_name(name)
            
            # In a real implementation, this would use property records API or web scraping
            # For demonstration, we'll simulate a property records search
            console.print("[bold yellow]Note:[/] This is a simulated property records search. In a real implementation, this would connect to property records databases.")
            
            with Progress() as progress:
                task = progress.add_task("[cyan]Searching property records...", total=100)
                
                # Simulate search progress
                for i in range(100):
                    progress.update(task, advance=1)
                    import time
                    time.sleep(0.02)
            
            # Simulate search results
            results = self._simulate_property_search(name, location)
            
            if results:
                # Display results
                table = Table(title=f"Property Records for {name} in {location}")
                table.add_column("Property Address", style="cyan")
                table.add_column("Owner Name", style="green")
                table.add_column("Purchase Date", style="yellow")
                table.add_column("Purchase Price", style="magenta")
                table.add_column("Property Type", style="blue")
                
                for property in results:
                    table.add_row(
                        property['address'],
                        property['owner_name'],
                        property['purchase_date'],
                        property['purchase_price'],
                        property['property_type']
                    )
                
                console.print(table)
                
                # Extract potential aliases
                aliases = set()
                for property in results:
                    aliases.add(property['owner_name'])
                
                # Remove the original name
                if name in aliases:
                    aliases.remove(name)
                
                # Add aliases to tracking database
                if aliases:
                    console.print(f"[bold green]Found {len(aliases)} potential aliases in property records.[/]")
                    
                    for alias in aliases:
                        self._add_alias(normalized_name, alias, "Property Records", 85)
                    
                    # Save the database
                    self.save_aliases_db()
                else:
                    console.print("[bold yellow]No new aliases found in property records.[/]")
            else:
                console.print("[bold yellow]No property records found for this name in the specified location.[/]")
            
            return results
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def cross_reference_aliases(self, name):
        """Cross-reference aliases across different sources."""
        console.print(f"[bold blue]Cross-referencing aliases for:[/] [bold green]{name}[/]")
        
        try:
            # Normalize the name
            normalized_name = self._normalize_name(name)
            
            # Check if we're tracking this name
            if normalized_name not in self.aliases_db:
                console.print(f"[bold yellow]Not tracking {name}. Please use track_alias() first.[/]")
                return None
            
            # Get aliases
            aliases = self.aliases_db[normalized_name]
            
            # Group aliases by source
            sources = {}
            for alias in aliases:
                source = alias['source']
                if source not in sources:
                    sources[source] = []
                sources[source].append(alias)
            
            # Display cross-reference table
            table = Table(title=f"Alias Cross-Reference for {name}")
            table.add_column("Alias", style="cyan")
            
            # Add a column for each source
            for source in sources.keys():
                table.add_column(source, style="green")
            
            # Get unique aliases
            unique_aliases = set()
            for alias in aliases:
                unique_aliases.add(alias['alias'])
            
            # Add rows for each alias
            for alias_name in unique_aliases:
                row = [alias_name]
                
                for source in sources.keys():
                    # Check if this alias appears in this source
                    found = False
                    confidence = 0
                    for alias in sources[source]:
                        if alias['alias'] == alias_name:
                            found = True
                            confidence = alias['confidence']
                            break
                    
                    if found:
                        row.append(f"✓ ({confidence}%)")
                    else:
                        row.append("✗")
                
                table.add_row(*row)
            
            console.print(table)
            
            # Calculate confidence scores for each alias
            confidence_scores = {}
            for alias_name in unique_aliases:
                total_confidence = 0
                count = 0
                
                for alias in aliases:
                    if alias['alias'] == alias_name:
                        total_confidence += alias['confidence']
                        count += 1
                
                if count > 0:
                    confidence_scores[alias_name] = total_confidence / count
            
            # Display overall confidence scores
            console.print("[bold]Overall Confidence Scores:[/]")
            for alias_name, score in sorted(confidence_scores.items(), key=lambda x: x[1], reverse=True):
                console.print(f"{alias_name}: [bold]{score:.2f}%[/]")
            
            return {
                'aliases': list(unique_aliases),
                'sources': sources,
                'confidence_scores': confidence_scores
            }
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def generate_alias_report(self, name, output_file=None):
        """Generate a comprehensive report on aliases for a name."""
        console.print(f"[bold blue]Generating alias report for:[/] [bold green]{name}[/]")
        
        try:
            # Normalize the name
            normalized_name = self._normalize_name(name)
            
            # Check if we're tracking this name
            if normalized_name not in self.aliases_db:
                console.print(f"[bold yellow]Not tracking {name}. Please use track_alias() first.[/]")
                return False
            
            # Cross-reference aliases
            cross_ref = self.cross_reference_aliases(name)
            
            if not cross_ref:
                console.print(f"[bold red]Error:[/] Failed to cross-reference aliases")
                return False
            
            # Determine output file
            if not output_file:
                output_file = f"alias_report_{normalized_name.replace(' ', '_')}.txt"
            
            # Generate report
            with open(output_file, 'w') as f:
                f.write(f"Alias Report for {name}\n")
                f.write(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")
                
                f.write("Summary:\n")
                f.write(f"- Primary Name: {name}\n")
                f.write(f"- Total Aliases Found: {len(cross_ref['aliases'])}\n")
                f.write(f"- Sources Checked: {len(cross_ref['sources'])}\n\n")
                
                f.write("Aliases by Confidence:\n")
                for alias_name, score in sorted(cross_ref['confidence_scores'].items(), key=lambda x: x[1], reverse=True):
                    f.write(f"- {alias_name}: {score:.2f}%\n")
                
                f.write("\nDetailed Source Information:\n")
                for source, aliases in cross_ref['sources'].items():
                    f.write(f"\n{source}:\n")
                    for alias in aliases:
                        f.write(f"- {alias['alias']} (Confidence: {alias['confidence']}%, Last Updated: {alias['last_updated']})\n")
                
                f.write("\nRecommendations:\n")
                high_confidence = [a for a, s in cross_ref['confidence_scores'].items() if s >= 80]
                medium_confidence = [a for a, s in cross_ref['confidence_scores'].items() if 50 <= s < 80]
                low_confidence = [a for a, s in cross_ref['confidence_scores'].items() if s < 50]
                
                f.write("High Confidence Aliases (Recommended for Investigation):\n")
                for alias in high_confidence:
                    f.write(f"- {alias}\n")
                
                f.write("\nMedium Confidence Aliases (Consider Investigation):\n")
                for alias in medium_confidence:
                    f.write(f"- {alias}\n")
                
                f.write("\nLow Confidence Aliases (Requires Verification):\n")
                for alias in low_confidence:
                    f.write(f"- {alias}\n")
            
            console.print(f"[bold green]Alias report generated and saved to:[/] [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def load_aliases_db(self):
        """Load aliases database from file."""
        db_file = os.path.expanduser("~/.pi_tool_aliases.json")
        
        if os.path.exists(db_file):
            try:
                with open(db_file, 'r') as f:
                    self.aliases_db = json.load(f)
                console.print(f"[bold green]Loaded aliases database with {len(self.aliases_db)} tracked names[/]")
            except Exception as e:
                console.print(f"[bold yellow]Warning:[/] Failed to load aliases database: {str(e)}")
                self.aliases_db = {}
        else:
            console.print("[bold blue]No existing aliases database found. Creating new database.[/]")
            self.aliases_db = {}
    
    def save_aliases_db(self):
        """Save aliases database to file."""
        db_file = os.path.expanduser("~/.pi_tool_aliases.json")
        
        try:
            with open(db_file, 'w') as f:
                json.dump(self.aliases_db, f, indent=2)
            console.print(f"[bold green]Saved aliases database with {len(self.aliases_db)} tracked names[/]")
            return True
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Failed to save aliases database: {str(e)}")
            return False
    
    def _normalize_name(self, name):
        """Normalize a name for consistent tracking."""
        # Convert to lowercase
        normalized = name.lower()
        
        # Remove extra whitespace
        normalized = ' '.join(normalized.split())
        
        return normalized
    
    def _search_local_db(self, normalized_name):
        """Search for a name in the local aliases database."""
        results = []
        
        # Check if we're tracking this name
        if normalized_name in self.aliases_db:
            # Return all aliases for this name
            results = self.aliases_db[normalized_name]
        else:
            # Check if this name is an alias for another name
            for primary_name, aliases in self.aliases_db.items():
                for alias in aliases:
                    if self._normalize_name(alias['alias']) == normalized_name:
                        # Add all aliases for the primary name
                        results = aliases
                        break
                
                if results:
                    break
        
        return results
    
    def _add_alias(self, normalized_name, alias, source, confidence):
        """Add an alias to the tracking database."""
        # Check if we're tracking this name
        if normalized_name not in self.aliases_db:
            self.aliases_db[normalized_name] = []
        
        # Check if this alias already exists for this name and source
        for existing_alias in self.aliases_db[normalized_name]:
            if existing_alias['alias'] == alias and existing_alias['source'] == source:
                # Update confidence and last_updated
                existing_alias['confidence'] = confidence
                existing_alias['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                console.print(f"[bold blue]Updated alias:[/] {alias} from {source} with confidence {confidence}%")
                return
        
        # Add new alias
        self.aliases_db[normalized_name].append({
            'alias': alias,
            'source': source,
            'confidence': confidence,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        console.print(f"[bold green]Added new alias:[/] {alias} from {source} with confidence {confidence}%")
    
    def _simulate_pacer_search(self, name):
        """Simulate a PACER search for demonstration purposes."""
        # This is a simulation - in a real implementation, this would connect to PACER
        
        # Generate some random results based on the name
        results = []
        
        # Split the name into parts
        name_parts = name.split()
        
        if len(name_parts) >= 2:
            # Simulate some name variations
            variations = [
                name,  # Original name
                f"{name_parts[0]} {name_parts[-1][0]}",  # First name + last initial
                f"{name_parts[0][0]} {name_parts[-1]}",  # First initial + last name
                f"{name_parts[-1]}, {name_parts[0]}",  # Last name, first name
            ]
            
            # Add some middle initial variations if there are more than 2 name parts
            if len(name_parts) > 2:
                variations.append(f"{name_parts[0]} {name_parts[1][0]} {name_parts[-1]}")  # First + middle initial + last
            
            # Generate some case numbers
            case_types = ["CV", "CR", "BK", "MC"]
            courts = ["NYSD", "CACD", "ILND", "TXSD", "FLSD"]
            years = ["18", "19", "20", "21", "22"]
            
            # Generate 3-5 random cases
            import random
            num_cases = random.randint(3, 5)
            
            for i in range(num_cases):
                case_type = random.choice(case_types)
                court = random.choice(courts)
                year = random.choice(years)
                case_num = random.randint(1000, 9999)
                
                # Random filing date
                month = random.randint(1, 12)
                day = random.randint(1, 28)
                filing_date = f"{year}-{month:02d}-{day:02d}"
                
                # Random party name from variations
                party_name = random.choice(variations)
                
                # Random role
                roles = ["Plaintiff", "Defendant", "Petitioner", "Respondent", "Debtor", "Creditor"]
                role = random.choice(roles)
                
                results.append({
                    'case_number': f"{case_type}-{year}-{case_num}",
                    'court': court,
                    'filing_date': filing_date,
                    'party_name': party_name,
                    'role': role
                })
        
        return results
    
    def _simulate_property_search(self, name, location):
        """Simulate a property records search for demonstration purposes."""
        # This is a simulation - in a real implementation, this would connect to property records databases
        
        # Generate some random results based on the name and location
        results = []
        
        # Split the name into parts
        name_parts = name.split()
        
        if len(name_parts) >= 2:
            # Simulate some name variations
            variations = [
                name,  # Original name
                f"{name_parts[-1]}, {name_parts[0]}",  # Last name, first name
            ]
            
            # Add spouse variation
            spouse_first_names = ["John", "Jane", "Michael", "Michelle", "David", "Sarah", "Robert", "Jennifer"]
            spouse_first = random.choice(spouse_first_names)
            variations.append(f"{name_parts[0]} & {spouse_first} {name_parts[-1]}")  # Name & Spouse Name
            
            # Generate some addresses
            streets = ["Main St", "Oak Ave", "Maple Dr", "Cedar Ln", "Pine Rd"]
            property_types = ["Single Family", "Condo", "Townhouse", "Multi-Family", "Vacant Land"]
            
            # Parse location
            location_parts = location.split(',')
            city = location_parts[0].strip() if len(location_parts) > 0 else "Springfield"
            
            # Generate 2-4 random properties
            import random
            num_properties = random.randint(2, 4)
            
            for i in range(num_properties):
                street_num = random.randint(100, 9999)
                street = random.choice(streets)
                
                # Random purchase date
                year = random.randint(2000, 2022)
                month = random.randint(1, 12)
                day = random.randint(1, 28)
                purchase_date = f"{year}-{month:02d}-{day:02d}"
                
                # Random purchase price
                purchase_price = f"${random.randint(100, 999)},{random.randint(100, 999)}"
                
                # Random property type
                property_type = random.choice(property_types)
                
                # Random owner name from variations
                owner_name = random.choice(variations)
                
                results.append({
                    'address': f"{street_num} {street}, {city}",
                    'owner_name': owner_name,
                    'purchase_date': purchase_date,
                    'purchase_price': purchase_price,
                    'property_type': property_type
                })
        
        return results
