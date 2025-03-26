"""
Identity Generator module for the Ultimate PI Tool.

This module provides functionality for generating synthetic identities with
realistic personal information.
"""

import os
import sys
import json
import random
import string
import datetime
from rich.console import Console
from rich.table import Table
import faker

console = Console()

class IdentityGenerator:
    """Identity Generator class for creating synthetic identities."""
    
    def __init__(self):
        """Initialize the Identity Generator module."""
        self.fake = faker.Faker()
        
        # Add localized providers
        self.locales = {
            "us": faker.Faker('en_US'),
            "uk": faker.Faker('en_GB'),
            "ca": faker.Faker('en_CA'),
            "au": faker.Faker('en_AU'),
            "fr": faker.Faker('fr_FR'),
            "de": faker.Faker('de_DE'),
            "es": faker.Faker('es_ES'),
            "it": faker.Faker('it_IT'),
            "jp": faker.Faker('ja_JP'),
            "cn": faker.Faker('zh_CN'),
            "ru": faker.Faker('ru_RU'),
            "br": faker.Faker('pt_BR'),
            "mx": faker.Faker('es_MX'),
            "in": faker.Faker('en_IN')
        }
    
    def generate_identity(self, locale="us", gender=None, age_min=18, age_max=80, 
                        include_ssn=True, include_credit_card=True, include_online=True):
        """Generate a complete synthetic identity."""
        console.print(f"[bold blue]Generating synthetic identity (locale: {locale})[/]")
        
        # Get appropriate faker instance
        fake = self.locales.get(locale.lower(), self.fake)
        
        # Determine gender
        if gender is None:
            gender = random.choice(["male", "female"])
        
        # Generate basic personal information
        if gender.lower() == "male":
            first_name = fake.first_name_male()
            prefix = random.choice(["Mr.", "Dr.", ""])
        else:
            first_name = fake.first_name_female()
            prefix = random.choice(["Ms.", "Mrs.", "Miss", "Dr.", ""])
        
        last_name = fake.last_name()
        middle_initial = random.choice(string.ascii_uppercase) + "."
        
        # Generate birthdate
        today = datetime.date.today()
        age = random.randint(age_min, age_max)
        birth_year = today.year - age
        birth_month = random.randint(1, 12)
        birth_day = random.randint(1, 28)  # Simplified to avoid month length issues
        birthdate = datetime.date(birth_year, birth_month, birth_day)
        
        # Generate address
        address = {
            "street": fake.street_address(),
            "city": fake.city(),
            "state": fake.state(),
            "state_abbr": fake.state_abbr(),
            "zipcode": fake.zipcode(),
            "country": fake.country()
        }
        
        # Generate contact information
        contact = {
            "phone": fake.phone_number(),
            "mobile": fake.phone_number(),
            "email": fake.email()
        }
        
        # Generate identification
        identification = {}
        if include_ssn:
            if locale.lower() == "us":
                identification["ssn"] = fake.ssn()
            elif locale.lower() == "uk":
                identification["nino"] = fake.bban()  # National Insurance number
            elif locale.lower() == "ca":
                identification["sin"] = f"{random.randint(100, 999)}-{random.randint(100, 999)}-{random.randint(100, 999)}"
            else:
                identification["national_id"] = fake.bban()
        
        identification["passport"] = f"{random.choice(string.ascii_uppercase)}{random.randint(10000000, 99999999)}"
        identification["drivers_license"] = f"{random.choice(string.ascii_uppercase)}{random.randint(1000000, 9999999)}"
        
        # Generate financial information
        financial = {}
        if include_credit_card:
            financial["credit_card"] = {
                "number": fake.credit_card_number(),
                "expiry": fake.credit_card_expire(),
                "provider": fake.credit_card_provider(),
                "security_code": fake.credit_card_security_code()
            }
        
        financial["bank"] = {
            "name": fake.company(),
            "account_number": fake.bban(),
            "routing_number": fake.iban()
        }
        
        # Generate employment information
        employment = {
            "company": fake.company(),
            "job_title": fake.job(),
            "department": random.choice(["Marketing", "Sales", "Engineering", "HR", "Finance", "Operations", "IT", "Customer Support"]),
            "salary": random.randint(30000, 150000)
        }
        
        # Generate online presence
        online = {}
        if include_online:
            username_base = f"{first_name.lower()}{last_name.lower()}{random.randint(1, 999)}"
            
            online["username"] = username_base
            online["password"] = fake.password(length=random.randint(10, 16))
            online["website"] = f"http://www.{last_name.lower()}{first_name.lower()}.com"
            online["social_media"] = {
                "twitter": f"@{username_base}",
                "instagram": username_base,
                "facebook": f"{first_name}.{last_name}.{random.randint(1, 999)}",
                "linkedin": f"{first_name}-{last_name}-{random.randint(1, 999)}"
            }
        
        # Generate physical characteristics
        physical = {
            "height_cm": random.randint(150, 200),
            "weight_kg": random.randint(50, 100),
            "blood_type": random.choice(["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]),
            "hair_color": random.choice(["Black", "Brown", "Blonde", "Red", "Gray", "White"]),
            "eye_color": random.choice(["Brown", "Blue", "Green", "Hazel", "Gray"])
        }
        
        # Compile identity
        identity = {
            "personal": {
                "prefix": prefix,
                "first_name": first_name,
                "middle_initial": middle_initial,
                "last_name": last_name,
                "full_name": f"{prefix} {first_name} {middle_initial} {last_name}".strip(),
                "gender": gender,
                "birthdate": birthdate.strftime("%Y-%m-%d"),
                "age": age
            },
            "address": address,
            "contact": contact,
            "identification": identification,
            "financial": financial,
            "employment": employment,
            "physical": physical
        }
        
        if include_online:
            identity["online"] = online
        
        # Display identity
        self._display_identity(identity)
        
        return identity
    
    def generate_multiple_identities(self, count=10, locale="us", gender=None, 
                                   age_min=18, age_max=80, include_ssn=True, 
                                   include_credit_card=True, include_online=True):
        """Generate multiple synthetic identities."""
        console.print(f"[bold blue]Generating {count} synthetic identities[/]")
        
        identities = []
        
        for i in range(count):
            # Randomize gender if not specified
            current_gender = gender
            if gender is None:
                current_gender = random.choice(["male", "female"])
            
            # Generate identity
            identity = self.generate_identity(
                locale=locale,
                gender=current_gender,
                age_min=age_min,
                age_max=age_max,
                include_ssn=include_ssn,
                include_credit_card=include_credit_card,
                include_online=include_online
            )
            
            identities.append(identity)
        
        return identities
    
    def generate_related_identities(self, count=2, relationship="family", locale="us", 
                                  age_min=18, age_max=80, include_ssn=True, 
                                  include_credit_card=True, include_online=True):
        """Generate related synthetic identities (family, business associates, etc.)."""
        console.print(f"[bold blue]Generating {count} related identities (relationship: {relationship})[/]")
        
        identities = []
        
        if relationship.lower() == "family":
            # Generate a family
            
            # Generate parents
            father = self.generate_identity(
                locale=locale,
                gender="male",
                age_min=max(age_min, 25),
                age_max=age_max,
                include_ssn=include_ssn,
                include_credit_card=include_credit_card,
                include_online=include_online
            )
            
            mother = self.generate_identity(
                locale=locale,
                gender="female",
                age_min=max(age_min, 25),
                age_max=age_max,
                include_ssn=include_ssn,
                include_credit_card=include_credit_card,
                include_online=include_online
            )
            
            # Make them a couple
            mother["personal"]["last_name"] = father["personal"]["last_name"]
            mother["address"] = father["address"].copy()
            
            identities.append(father)
            identities.append(mother)
            
            # Generate children if needed
            remaining = count - 2
            if remaining > 0:
                min_parent_age = min(father["personal"]["age"], mother["personal"]["age"])
                
                for i in range(remaining):
                    child_age = random.randint(1, min_parent_age - 18)
                    child_gender = random.choice(["male", "female"])
                    
                    child = self.generate_identity(
                        locale=locale,
                        gender=child_gender,
                        age_min=child_age,
                        age_max=child_age,
                        include_ssn=include_ssn,
                        include_credit_card=False if child_age < 18 else include_credit_card,
                        include_online=False if child_age < 13 else include_online
                    )
                    
                    # Make them part of the family
                    child["personal"]["last_name"] = father["personal"]["last_name"]
                    child["address"] = father["address"].copy()
                    
                    identities.append(child)
        
        elif relationship.lower() == "business":
            # Generate business associates
            
            # Generate a company
            fake = self.locales.get(locale.lower(), self.fake)
            company_name = fake.company()
            company_address = {
                "street": fake.street_address(),
                "city": fake.city(),
                "state": fake.state(),
                "state_abbr": fake.state_abbr(),
                "zipcode": fake.zipcode(),
                "country": fake.country()
            }
            
            # Generate employees
            for i in range(count):
                gender = random.choice(["male", "female"])
                
                employee = self.generate_identity(
                    locale=locale,
                    gender=gender,
                    age_min=age_min,
                    age_max=age_max,
                    include_ssn=include_ssn,
                    include_credit_card=include_credit_card,
                    include_online=include_online
                )
                
                # Make them work for the same company
                employee["employment"]["company"] = company_name
                
                # Assign job titles based on position
                if i == 0:
                    employee["employment"]["job_title"] = "CEO"
                    employee["employment"]["department"] = "Executive"
                    employee["employment"]["salary"] = random.randint(150000, 500000)
                elif i == 1:
                    employee["employment"]["job_title"] = "CTO"
                    employee["employment"]["department"] = "Executive"
                    employee["employment"]["salary"] = random.randint(120000, 300000)
                elif i == 2:
                    employee["employment"]["job_title"] = "CFO"
                    employee["employment"]["department"] = "Executive"
                    employee["employment"]["salary"] = random.randint(120000, 300000)
                else:
                    departments = ["Marketing", "Sales", "Engineering", "HR", "Finance", "Operations", "IT", "Customer Support"]
                    titles = ["Manager", "Director", "Lead", "Senior Specialist", "Coordinator", "Analyst"]
                    
                    employee["employment"]["department"] = random.choice(departments)
                    employee["employment"]["job_title"] = f"{random.choice(titles)}, {employee['employment']['department']}"
                    employee["employment"]["salary"] = random.randint(60000, 120000)
                
                identities.append(employee)
        
        else:
            # Generate unrelated identities
            for i in range(count):
                gender = random.choice(["male", "female"])
                
                identity = self.generate_identity(
                    locale=locale,
                    gender=gender,
                    age_min=age_min,
                    age_max=age_max,
                    include_ssn=include_ssn,
                    include_credit_card=include_credit_card,
                    include_online=include_online
                )
                
                identities.append(identity)
        
        return identities
    
    def save_to_file(self, identities, output_file):
        """Save generated identities to a file."""
        console.print(f"[bold blue]Saving {len(identities)} identities to:[/] [bold green]{output_file}[/]")
        
        try:
            # Convert dates to strings for JSON serialization
            for identity in identities:
                if isinstance(identity, dict) and "personal" in identity and "birthdate" in identity["personal"]:
                    if isinstance(identity["personal"]["birthdate"], datetime.date):
                        identity["personal"]["birthdate"] = identity["personal"]["birthdate"].strftime("%Y-%m-%d")
            
            with open(output_file, 'w') as f:
                json.dump(identities, f, indent=2)
            
            console.print(f"[bold green]Identities saved successfully![/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error saving identities:[/] {str(e)}")
            return False
    
    def _display_identity(self, identity):
        """Display a synthetic identity in a readable format."""
        # Create personal information table
        personal_table = Table(title="Personal Information")
        personal_table.add_column("Attribute", style="cyan")
        personal_table.add_column("Value", style="green")
        
        for key, value in identity["personal"].items():
            personal_table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(personal_table)
        
        # Create address table
        address_table = Table(title="Address")
        address_table.add_column("Attribute", style="cyan")
        address_table.add_column("Value", style="green")
        
        for key, value in identity["address"].items():
            address_table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(address_table)
        
        # Create contact table
        contact_table = Table(title="Contact Information")
        contact_table.add_column("Attribute", style="cyan")
        contact_table.add_column("Value", style="green")
        
        for key, value in identity["contact"].items():
            contact_table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(contact_table)
        
        # Create identification table
        id_table = Table(title="Identification")
        id_table.add_column("Attribute", style="cyan")
        id_table.add_column("Value", style="green")
        
        for key, value in identity["identification"].items():
            id_table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(id_table)
        
        # Create employment table
        employment_table = Table(title="Employment")
        employment_table.add_column("Attribute", style="cyan")
        employment_table.add_column("Value", style="green")
        
        for key, value in identity["employment"].items():
            employment_table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(employment_table)
        
        # Create financial table if credit card is included
        if "credit_card" in identity["financial"]:
            financial_table = Table(title="Financial Information")
            financial_table.add_column("Attribute", style="cyan")
            financial_table.add_column("Value", style="green")
            
            for cc_key, cc_value in identity["financial"]["credit_card"].items():
                financial_table.add_row(f"Credit Card {cc_key.replace('_', ' ').title()}", str(cc_value))
            
            for bank_key, bank_value in identity["financial"]["bank"].items():
                financial_table.add_row(f"Bank {bank_key.replace('_', ' ').title()}", str(bank_value))
            
            console.print(financial_table)
        
        # Create online presence table if included
        if "online" in identity:
            online_table = Table(title="Online Presence")
            online_table.add_column("Attribute", style="cyan")
            online_table.add_column("Value", style="green")
            
            online_table.add_row("Username", identity["online"]["username"])
            online_table.add_row("Password", identity["online"]["password"])
            online_table.add_row("Website", identity["online"]["website"])
            
            for sm_key, sm_value in identity["online"]["social_media"].items():
                online_table.add_row(f"{sm_key.replace('_', ' ').title()}", str(sm_value))
            
            console.print(online_table)
        
        # Create physical characteristics table
        physical_table = Table(title="Physical Characteristics")
        physical_table.add_column("Attribute", style="cyan")
        physical_table.add_column("Value", style="green")
        
        for key, value in identity["physical"].items():
            physical_table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(physical_table)
