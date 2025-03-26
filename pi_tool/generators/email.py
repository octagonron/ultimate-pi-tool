"""
Email Generator module for the Ultimate PI Tool.

This module provides functionality for generating email addresses based on
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

class EmailGenerator:
    """Email Generator class for creating email addresses based on personal information."""
    
    def __init__(self):
        """Initialize the Email Generator module."""
        self.common_patterns = [
            "{first}@{domain}",
            "{last}@{domain}",
            "{first}{last}@{domain}",
            "{first}.{last}@{domain}",
            "{first}_{last}@{domain}",
            "{first}-{last}@{domain}",
            "{first}{last_initial}@{domain}",
            "{first_initial}{last}@{domain}",
            "{first_initial}{middle_initial}{last}@{domain}",
            "{first}{birth_year}@{domain}",
            "{first}{last}{birth_year}@{domain}",
            "{last}{first}@{domain}",
            "{first}{last_initial}{birth_year}@{domain}",
            "{first}{middle_initial}{last}@{domain}",
            "{nickname}@{domain}",
            "{nickname}{birth_year}@{domain}",
            "{first}{random_number}@{domain}",
            "{last}{random_number}@{domain}",
            "{first}{last}{random_number}@{domain}",
            "{profession}{random_number}@{domain}"
        ]
        
        self.common_domains = [
            "gmail.com",
            "yahoo.com",
            "hotmail.com",
            "outlook.com",
            "aol.com",
            "icloud.com",
            "protonmail.com",
            "mail.com",
            "zoho.com",
            "yandex.com",
            "gmx.com",
            "tutanota.com",
            "fastmail.com",
            "mailbox.org",
            "posteo.de",
            "disroot.org",
            "pm.me",
            "cock.li",
            "riseup.net",
            "mail.ru",
            "inbox.com",
            "hushmail.com",
            "lycos.com",
            "rediffmail.com",
            "live.com",
            "msn.com",
            "me.com",
            "mac.com"
        ]
        
        self.business_domains = [
            "company.com",
            "business.com",
            "enterprise.com",
            "corp.com",
            "inc.com",
            "ltd.com",
            "agency.com",
            "firm.com",
            "group.com",
            "team.com",
            "solutions.com",
            "services.com",
            "consulting.com",
            "associates.com",
            "partners.com",
            "global.com",
            "international.com",
            "worldwide.com",
            "systems.com",
            "technologies.com",
            "tech.com",
            "digital.com",
            "media.com",
            "creative.com",
            "design.com",
            "studio.com",
            "productions.com",
            "network.com",
            "web.com",
            "online.com",
            "cloud.com",
            "software.com",
            "app.com",
            "mobile.com",
            "data.com",
            "analytics.com",
            "research.com",
            "labs.com",
            "science.com",
            "education.com",
            "academy.com",
            "institute.com",
            "foundation.com",
            "org.com",
            "nonprofit.com"
        ]
        
        self.disposable_domains = [
            "temp-mail.org",
            "guerrillamail.com",
            "10minutemail.com",
            "mailinator.com",
            "throwawaymail.com",
            "tempmail.com",
            "fakeinbox.com",
            "yopmail.com",
            "dispostable.com",
            "maildrop.cc",
            "getnada.com",
            "mailnesia.com",
            "tempr.email",
            "tempmail.net",
            "emailondeck.com",
            "spamgourmet.com",
            "mytemp.email",
            "burnermail.io",
            "trashmail.com",
            "sharklasers.com",
            "guerrillamail.info",
            "grr.la",
            "spam4.me",
            "mailcatch.com",
            "tempmailaddress.com",
            "mintemail.com",
            "mohmal.com",
            "tempail.com",
            "33mail.com",
            "jetable.org"
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
    
    def generate_from_personal_info(self, first_name=None, middle_name=None, last_name=None, 
                                   nickname=None, birth_year=None, profession=None, 
                                   custom_domains=None, count=10, include_leet=True, include_random=True):
        """Generate email addresses based on personal information."""
        console.print(f"[bold blue]Generating email addresses from personal information[/]")
        
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
            "profession": profession.lower() if profession else ""
        }
        
        # Add initials
        data["first_initial"] = data["first"][0] if data["first"] else ""
        data["middle_initial"] = data["middle"][0] if data["middle"] else ""
        data["last_initial"] = data["last"][0] if data["last"] else ""
        
        # Determine domains to use
        domains = self.common_domains.copy()
        if custom_domains:
            domains.extend(custom_domains)
        
        # Generate email addresses
        emails = []
        
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
            if "{profession}" in pattern and not data["profession"]:
                continue
            
            # Generate email from pattern
            for domain in random.sample(domains, min(5, len(domains))):
                email = pattern
                
                # Replace domain placeholder
                email = email.replace("{domain}", domain)
                
                # Replace other placeholders
                for key, value in data.items():
                    placeholder = "{" + key + "}"
                    if placeholder in email:
                        email = email.replace(placeholder, value)
                
                # Add random number if needed
                if "{random_number}" in email and include_random:
                    email = email.replace("{random_number}", str(random.randint(1, 999)))
                
                # Add email if valid
                if email and all(char not in email for char in "{}"):
                    emails.append(email)
        
        # Add leet speak variations
        if include_leet:
            leet_emails = []
            for email in random.sample(emails, min(10, len(emails))):
                parts = email.split('@')
                if len(parts) == 2:
                    username, domain = parts
                    leet_username = self._apply_leet_speak(username)
                    if leet_username != username:
                        leet_emails.append(f"{leet_username}@{domain}")
            emails.extend(leet_emails)
        
        # Remove duplicates and limit to count
        emails = list(set(emails))
        emails = random.sample(emails, min(count, len(emails)))
        
        # Display results
        self._display_emails(emails)
        
        return emails
    
    def generate_business_emails(self, first_name=None, last_name=None, company_name=None, 
                               position=None, custom_domains=None, count=10):
        """Generate business email addresses."""
        console.print(f"[bold blue]Generating business email addresses[/]")
        
        # Validate inputs
        if not any([first_name, last_name]):
            console.print("[bold red]Error:[/] At least one of first_name or last_name must be provided")
            return []
        
        # Prepare data
        data = {
            "first": first_name.lower() if first_name else "",
            "last": last_name.lower() if last_name else "",
            "position": position.lower() if position else ""
        }
        
        # Add initials
        data["first_initial"] = data["first"][0] if data["first"] else ""
        data["last_initial"] = data["last"][0] if data["last"] else ""
        
        # Determine domains to use
        if company_name:
            # Create company domain
            company_domain = company_name.lower().replace(" ", "")
            domains = [f"{company_domain}.com"]
            
            # Add variations
            domains.append(f"{company_domain}.co")
            domains.append(f"{company_domain}.io")
            domains.append(f"{company_domain}.net")
            domains.append(f"{company_domain}.org")
        else:
            domains = self.business_domains.copy()
        
        if custom_domains:
            domains.extend(custom_domains)
        
        # Define business email patterns
        business_patterns = [
            "{first}@{domain}",
            "{last}@{domain}",
            "{first}.{last}@{domain}",
            "{first}_{last}@{domain}",
            "{first}-{last}@{domain}",
            "{first_initial}{last}@{domain}",
            "{first_initial}.{last}@{domain}",
            "{first}.{last_initial}@{domain}",
            "{first_initial}{last_initial}@{domain}",
            "{first}{last_initial}@{domain}"
        ]
        
        # Add position-based patterns if position is provided
        if data["position"]:
            business_patterns.extend([
                "{position}@{domain}",
                "{first}.{position}@{domain}",
                "{position}.{last}@{domain}"
            ])
        
        # Generate email addresses
        emails = []
        
        # Apply patterns
        for pattern in business_patterns:
            # Skip patterns that require missing data
            if "{first}" in pattern and not data["first"]:
                continue
            if "{last}" in pattern and not data["last"]:
                continue
            if "{position}" in pattern and not data["position"]:
                continue
            
            # Generate email from pattern
            for domain in random.sample(domains, min(5, len(domains))):
                email = pattern
                
                # Replace domain placeholder
                email = email.replace("{domain}", domain)
                
                # Replace other placeholders
                for key, value in data.items():
                    placeholder = "{" + key + "}"
                    if placeholder in email:
                        email = email.replace(placeholder, value)
                
                # Add email if valid
                if email and all(char not in email for char in "{}"):
                    emails.append(email)
        
        # Remove duplicates and limit to count
        emails = list(set(emails))
        emails = random.sample(emails, min(count, len(emails)))
        
        # Display results
        self._display_emails(emails)
        
        return emails
    
    def generate_disposable_emails(self, base_username=None, count=10):
        """Generate disposable email addresses."""
        console.print(f"[bold blue]Generating disposable email addresses[/]")
        
        # Generate base username if not provided
        if not base_username:
            letters = string.ascii_lowercase
            digits = string.digits
            base_username = ''.join(random.choice(letters + digits) for _ in range(8))
        
        # Generate email addresses
        emails = []
        
        # Apply domains
        for domain in random.sample(self.disposable_domains, min(count, len(self.disposable_domains))):
            emails.append(f"{base_username}@{domain}")
        
        # Add variations if needed
        if len(emails) < count:
            # Add random suffixes
            for domain in random.sample(self.disposable_domains, min(count - len(emails), len(self.disposable_domains))):
                suffix = ''.join(random.choice(string.digits) for _ in range(3))
                emails.append(f"{base_username}{suffix}@{domain}")
        
        # Remove duplicates and limit to count
        emails = list(set(emails))
        emails = random.sample(emails, min(count, len(emails)))
        
        # Display results
        self._display_emails(emails)
        
        return emails
    
    def generate_from_username(self, username, count=10):
        """Generate email addresses from a username."""
        console.print(f"[bold blue]Generating email addresses from username:[/] [bold green]{username}[/]")
        
        if not username:
            console.print("[bold red]Error:[/] Username must be provided")
            return []
        
        # Generate email addresses
        emails = []
        
        # Apply domains
        domains = random.sample(self.common_domains, min(count, len(self.common_domains)))
        for domain in domains:
            emails.append(f"{username}@{domain}")
        
        # Add variations if needed
        if len(emails) < count:
            # Add random suffixes
            for domain in random.sample(self.common_domains, min(count - len(emails), len(self.common_domains))):
                suffix = ''.join(random.choice(string.digits) for _ in range(2))
                emails.append(f"{username}{suffix}@{domain}")
        
        # Remove duplicates and limit to count
        emails = list(set(emails))
        emails = random.sample(emails, min(count, len(emails)))
        
        # Display results
        self._display_emails(emails)
        
        return emails
    
    def check_validity(self, emails):
        """Check email address validity."""
        console.print(f"[bold blue]Checking validity for {len(emails)} email addresses[/]")
        
        # Create results table
        table = Table(title="Email Validity Check")
        table.add_column("Email", style="cyan")
        table.add_column("Valid Format", style="green")
        table.add_column("Domain Exists", style="yellow")
        table.add_column("MX Records", style="magenta")
        
        # Check validity (simulated)
        for email in emails:
            # Check format
            format_valid = self._check_email_format(email)
            
            # Check domain (simulated)
            domain = email.split('@')[-1]
            domain_exists = domain in self.common_domains or domain in self.business_domains or domain in self.disposable_domains
            
            # Check MX records (simulated)
            mx_records = "✅" if domain_exists else "❌"
            
            table.add_row(
                email,
                "✅" if format_valid else "❌",
                "✅" if domain_exists else "❌",
                mx_records
            )
        
        console.print(table)
        
        return table
    
    def save_to_file(self, emails, output_file):
        """Save generated email addresses to a file."""
        console.print(f"[bold blue]Saving {len(emails)} email addresses to:[/] [bold green]{output_file}[/]")
        
        try:
            with open(output_file, 'w') as f:
                for email in emails:
                    f.write(f"{email}\n")
            
            console.print(f"[bold green]Email addresses saved successfully![/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error saving email addresses:[/] {str(e)}")
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
    
    def _check_email_format(self, email):
        """Check if an email address has a valid format."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _display_emails(self, emails):
        """Display generated email addresses in a table."""
        table = Table(title=f"Generated Email Addresses ({len(emails)})")
        table.add_column("Email", style="cyan")
        table.add_column("Domain", style="green")
        
        for email in emails:
            parts = email.split('@')
            if len(parts) == 2:
                username, domain = parts
                table.add_row(email, domain)
            else:
                table.add_row(email, "Invalid")
        
        console.print(table)
