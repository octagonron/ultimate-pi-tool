"""
Username Generator module for the Ultimate PI Tool.

This module provides functionality for generating usernames based on
personal information, patterns, and variations.
"""

import os
import sys
import json
import random
import string
from rich.console import Console
from rich.table import Table
import itertools

console = Console()

class UsernameGenerator:
    """Username Generator class for creating usernames based on personal information."""
    
    def __init__(self):
        """Initialize the Username Generator module."""
        self.common_patterns = [
            "{first}",
            "{last}",
            "{first}{last}",
            "{first}.{last}",
            "{first}_{last}",
            "{first}-{last}",
            "{first}{last_initial}",
            "{first_initial}{last}",
            "{first_initial}{middle_initial}{last}",
            "{first}{birth_year}",
            "{first}{last}{birth_year}",
            "{last}{first}",
            "{first}{last_initial}{birth_year}",
            "{first}{middle_initial}{last}",
            "{nickname}",
            "{nickname}{birth_year}",
            "{first}{random_number}",
            "{last}{random_number}",
            "{first}{last}{random_number}",
            "{hobby}{random_number}",
            "{profession}{random_number}",
            "{location}{random_number}"
        ]
        
        self.leet_map = {
            'a': ['4', '@'],
            'b': ['8'],
            'e': ['3'],
            'g': ['6', '9'],
            'i': ['1', '!'],
            'l': ['1', '|'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7', '+'],
            'z': ['2']
        }
        
        self.common_suffixes = [
            "123", "1234", "12345", "321", "xyz", "abc", "007", "420", "69", "666", "777", "888", "999",
            "2020", "2021", "2022", "2023", "2024", "2025", "xoxo", "pro", "master", "guru", "expert",
            "fan", "lover", "hater", "king", "queen", "boss", "chief", "admin", "user", "gamer", "player",
            "coder", "dev", "hacker", "geek", "nerd", "tech", "official", "real", "original", "genuine",
            "elite", "prime", "ultra", "mega", "super", "hyper", "extreme", "ultimate", "supreme", "alpha",
            "beta", "omega", "delta", "sigma", "gamma", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
            "lambda", "mu", "nu", "xi", "omicron", "pi", "rho", "tau", "upsilon", "phi", "chi", "psi"
        ]
        
        self.common_prefixes = [
            "the", "mr", "ms", "miss", "mrs", "dr", "prof", "sir", "lord", "lady", "king", "queen", "prince",
            "princess", "duke", "duchess", "count", "countess", "baron", "baroness", "emperor", "empress",
            "czar", "sultan", "khan", "chief", "boss", "admin", "super", "mega", "ultra", "hyper", "extreme",
            "ultimate", "supreme", "elite", "prime", "pro", "master", "guru", "expert", "genius", "wizard",
            "ninja", "samurai", "warrior", "knight", "paladin", "ranger", "rogue", "mage", "warlock", "druid",
            "shaman", "priest", "monk", "hunter", "assassin", "sniper", "soldier", "captain", "commander",
            "general", "admiral", "pilot", "astronaut", "cosmonaut", "explorer", "adventurer", "traveler",
            "wanderer", "nomad", "vagabond", "drifter", "roamer", "rover", "scout", "spy", "agent", "detective",
            "inspector", "investigator", "sleuth", "sherlock", "watson", "holmes", "moriarty", "poirot", "marple"
        ]
    
    def generate_from_personal_info(self, first_name=None, middle_name=None, last_name=None, 
                                   nickname=None, birth_year=None, hobbies=None, profession=None, 
                                   location=None, count=10, include_leet=True, include_random=True):
        """Generate usernames based on personal information."""
        console.print(f"[bold blue]Generating usernames from personal information[/]")
        
        # Validate inputs
        if not any([first_name, last_name, nickname]):
            console.print("[bold red]Error:[/] At least one of first_name, last_name, or nickname must be provided")
            return []
        
        # Prepare data
        data = {
            "first": first_name.lower() if first_name else "",
            "last": last_name.lower() if last_name else "",
            "middle": middle_name.lower() if middle_name else "",
            "nickname": nickname.lower() if nickname else "",
            "birth_year": str(birth_year) if birth_year else "",
            "hobby": random.choice(hobbies).lower() if hobbies else "",
            "profession": profession.lower() if profession else "",
            "location": location.lower() if location else ""
        }
        
        # Add initials
        data["first_initial"] = data["first"][0] if data["first"] else ""
        data["middle_initial"] = data["middle"][0] if data["middle"] else ""
        data["last_initial"] = data["last"][0] if data["last"] else ""
        
        # Generate usernames
        usernames = []
        
        # Apply patterns
        for pattern in self.common_patterns:
            # Skip patterns that require missing data
            if "{first}" in pattern and not data["first"]:
                continue
            if "{last}" in pattern and not data["last"]:
                continue
            if "{middle_initial}" in pattern and not data["middle_initial"]:
                continue
            if "{nickname}" in pattern and not data["nickname"]:
                continue
            if "{birth_year}" in pattern and not data["birth_year"]:
                continue
            if "{hobby}" in pattern and not data["hobby"]:
                continue
            if "{profession}" in pattern and not data["profession"]:
                continue
            if "{location}" in pattern and not data["location"]:
                continue
            
            # Generate username from pattern
            username = pattern
            
            # Replace placeholders
            for key, value in data.items():
                placeholder = "{" + key + "}"
                if placeholder in username:
                    username = username.replace(placeholder, value)
            
            # Add random number if needed
            if "{random_number}" in username and include_random:
                username = username.replace("{random_number}", str(random.randint(1, 999)))
            
            # Add username if valid
            if username and all(char not in username for char in "{}"):
                usernames.append(username)
        
        # Add variations with common prefixes and suffixes
        base_usernames = usernames.copy()
        for username in base_usernames:
            # Add prefixes
            for prefix in random.sample(self.common_prefixes, min(5, len(self.common_prefixes))):
                usernames.append(f"{prefix}{username}")
            
            # Add suffixes
            for suffix in random.sample(self.common_suffixes, min(5, len(self.common_suffixes))):
                usernames.append(f"{username}{suffix}")
        
        # Add leet speak variations
        if include_leet:
            leet_usernames = []
            for username in random.sample(usernames, min(10, len(usernames))):
                leet_username = self._apply_leet_speak(username)
                if leet_username != username:
                    leet_usernames.append(leet_username)
            usernames.extend(leet_usernames)
        
        # Remove duplicates and limit to count
        usernames = list(set(usernames))
        usernames = random.sample(usernames, min(count, len(usernames)))
        
        # Display results
        self._display_usernames(usernames)
        
        return usernames
    
    def generate_variations(self, base_username, count=10, include_leet=True, include_random=True):
        """Generate variations of a base username."""
        console.print(f"[bold blue]Generating variations of:[/] [bold green]{base_username}[/]")
        
        if not base_username:
            console.print("[bold red]Error:[/] Base username must be provided")
            return []
        
        variations = [base_username]
        
        # Add common prefixes
        for prefix in random.sample(self.common_prefixes, min(5, len(self.common_prefixes))):
            variations.append(f"{prefix}{base_username}")
        
        # Add common suffixes
        for suffix in random.sample(self.common_suffixes, min(5, len(self.common_suffixes))):
            variations.append(f"{base_username}{suffix}")
        
        # Add random numbers
        if include_random:
            for _ in range(5):
                variations.append(f"{base_username}{random.randint(1, 999)}")
        
        # Add leet speak variations
        if include_leet:
            leet_variations = []
            for variation in variations:
                leet_variation = self._apply_leet_speak(variation)
                if leet_variation != variation:
                    leet_variations.append(leet_variation)
            variations.extend(leet_variations)
        
        # Add case variations
        case_variations = []
        for variation in variations:
            # Capitalize first letter
            case_variations.append(variation.capitalize())
            
            # Capitalize each word
            if " " in variation:
                case_variations.append(variation.title())
            
            # ALL CAPS
            case_variations.append(variation.upper())
        
        variations.extend(case_variations)
        
        # Add separator variations
        separator_variations = []
        for variation in variations:
            if " " in variation:
                separator_variations.append(variation.replace(" ", "_"))
                separator_variations.append(variation.replace(" ", "-"))
                separator_variations.append(variation.replace(" ", "."))
                separator_variations.append(variation.replace(" ", ""))
        
        variations.extend(separator_variations)
        
        # Remove duplicates and limit to count
        variations = list(set(variations))
        variations = random.sample(variations, min(count, len(variations)))
        
        # Display results
        self._display_usernames(variations)
        
        return variations
    
    def generate_from_keywords(self, keywords, count=10, include_leet=True, include_random=True):
        """Generate usernames from a list of keywords."""
        console.print(f"[bold blue]Generating usernames from keywords:[/] [bold green]{', '.join(keywords)}[/]")
        
        if not keywords:
            console.print("[bold red]Error:[/] Keywords must be provided")
            return []
        
        usernames = []
        
        # Generate combinations of keywords
        for r in range(1, min(4, len(keywords) + 1)):
            for combo in itertools.combinations(keywords, r):
                # Join keywords
                username = "".join(combo)
                usernames.append(username)
                
                # Join with separators
                usernames.append("_".join(combo))
                usernames.append("-".join(combo))
                usernames.append(".".join(combo))
        
        # Add common prefixes and suffixes
        base_usernames = usernames.copy()
        for username in base_usernames:
            # Add prefixes
            for prefix in random.sample(self.common_prefixes, min(3, len(self.common_prefixes))):
                usernames.append(f"{prefix}{username}")
            
            # Add suffixes
            for suffix in random.sample(self.common_suffixes, min(3, len(self.common_suffixes))):
                usernames.append(f"{username}{suffix}")
        
        # Add random numbers
        if include_random:
            random_usernames = []
            for username in random.sample(usernames, min(10, len(usernames))):
                random_usernames.append(f"{username}{random.randint(1, 999)}")
            usernames.extend(random_usernames)
        
        # Add leet speak variations
        if include_leet:
            leet_usernames = []
            for username in random.sample(usernames, min(10, len(usernames))):
                leet_username = self._apply_leet_speak(username)
                if leet_username != username:
                    leet_usernames.append(leet_username)
            usernames.extend(leet_usernames)
        
        # Remove duplicates and limit to count
        usernames = list(set(usernames))
        usernames = random.sample(usernames, min(count, len(usernames)))
        
        # Display results
        self._display_usernames(usernames)
        
        return usernames
    
    def generate_random(self, length_min=6, length_max=12, count=10, include_numbers=True, include_special=False):
        """Generate random usernames."""
        console.print(f"[bold blue]Generating random usernames[/]")
        
        usernames = []
        
        # Define character sets
        letters = string.ascii_lowercase
        numbers = string.digits if include_numbers else ""
        special = "_-." if include_special else ""
        chars = letters + numbers + special
        
        # Generate random usernames
        for _ in range(count * 2):  # Generate more than needed to account for duplicates
            # Determine length
            length = random.randint(length_min, length_max)
            
            # Generate username
            username = ""
            
            # First character should be a letter
            username += random.choice(letters)
            
            # Rest of the characters
            username += "".join(random.choice(chars) for _ in range(length - 1))
            
            usernames.append(username)
        
        # Remove duplicates and limit to count
        usernames = list(set(usernames))
        usernames = random.sample(usernames, min(count, len(usernames)))
        
        # Display results
        self._display_usernames(usernames)
        
        return usernames
    
    def check_availability(self, usernames, platforms=None):
        """Check username availability across platforms."""
        console.print(f"[bold blue]Checking availability for {len(usernames)} usernames[/]")
        
        # Define platforms to check if not provided
        if not platforms:
            platforms = [
                "twitter", "instagram", "facebook", "tiktok", "youtube", "reddit", "github", "linkedin",
                "pinterest", "snapchat", "twitch", "discord", "telegram", "whatsapp", "signal", "tumblr",
                "medium", "quora", "stackoverflow", "hackernews", "producthunt", "behance", "dribbble",
                "deviantart", "flickr", "500px", "vimeo", "soundcloud", "spotify", "apple", "microsoft",
                "google", "amazon", "netflix", "hulu", "disney", "steam", "epic", "ubisoft", "ea", "blizzard",
                "nintendo", "playstation", "xbox", "oculus", "vive", "valve", "unity", "unreal", "godot"
            ]
        
        # Create results table
        table = Table(title="Username Availability")
        table.add_column("Username", style="cyan")
        
        for platform in platforms:
            table.add_column(platform.capitalize(), style="green")
        
        # Check availability (simulated)
        for username in usernames:
            row = [username]
            
            for platform in platforms:
                # Simulate availability check
                # In a real implementation, this would make API calls or web scraping
                availability = random.choice(["✅", "❌"])
                row.append(availability)
            
            table.add_row(*row)
        
        console.print(table)
        
        return table
    
    def save_to_file(self, usernames, output_file):
        """Save generated usernames to a file."""
        console.print(f"[bold blue]Saving {len(usernames)} usernames to:[/] [bold green]{output_file}[/]")
        
        try:
            with open(output_file, 'w') as f:
                for username in usernames:
                    f.write(f"{username}\n")
            
            console.print(f"[bold green]Usernames saved successfully![/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error saving usernames:[/] {str(e)}")
            return False
    
    def _apply_leet_speak(self, text):
        """Apply leet speak transformations to text."""
        leet_text = ""
        
        for char in text:
            if char.lower() in self.leet_map and random.random() < 0.3:  # 30% chance to apply leet
                leet_char = random.choice(self.leet_map[char.lower()])
                leet_text += leet_char
            else:
                leet_text += char
        
        return leet_text
    
    def _display_usernames(self, usernames):
        """Display generated usernames in a table."""
        table = Table(title=f"Generated Usernames ({len(usernames)})")
        table.add_column("Username", style="cyan")
        table.add_column("Length", style="green")
        
        for username in usernames:
            table.add_row(username, str(len(username)))
        
        console.print(table)
