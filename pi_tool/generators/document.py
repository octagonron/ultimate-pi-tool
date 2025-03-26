"""
Document Generator module for the Ultimate PI Tool.

This module provides functionality for generating various types of documents
including reports, forms, and fake identification documents.
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
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table as PDFTable
from reportlab.platypus import TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from PIL import Image as PILImage, ImageDraw, ImageFont

console = Console()

class DocumentGenerator:
    """Document Generator class for creating various types of documents."""
    
    def __init__(self):
        """Initialize the Document Generator module."""
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
        
        # Define document types
        self.document_types = [
            "report", "invoice", "receipt", "contract", "letter", "resume",
            "id_card", "passport", "drivers_license", "birth_certificate",
            "medical_record", "bank_statement", "tax_form", "utility_bill"
        ]
    
    def generate_report(self, title=None, sections=None, identity=None, output_file=None):
        """Generate a professional-looking report document."""
        console.print(f"[bold blue]Generating report document[/]")
        
        # Generate title if not provided
        if not title:
            title = f"Report on {self.fake.bs()}"
        
        # Generate sections if not provided
        if not sections:
            sections = []
            section_count = random.randint(3, 7)
            
            for i in range(section_count):
                section_title = self.fake.catch_phrase()
                paragraphs = []
                
                paragraph_count = random.randint(2, 5)
                for j in range(paragraph_count):
                    paragraphs.append(self.fake.paragraph(nb_sentences=random.randint(3, 8)))
                
                sections.append({
                    "title": section_title,
                    "content": paragraphs
                })
        
        # Generate author if not provided
        if not identity:
            identity = {
                "personal": {
                    "full_name": self.fake.name(),
                    "job_title": self.fake.job()
                },
                "contact": {
                    "email": self.fake.email(),
                    "phone": self.fake.phone_number()
                },
                "employment": {
                    "company": self.fake.company()
                }
            }
        
        # Generate date
        report_date = datetime.date.today().strftime("%B %d, %Y")
        
        # Determine output file if not provided
        if not output_file:
            output_file = f"report_{title.lower().replace(' ', '_')[:20]}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Create custom styles
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Title'],
            fontSize=18,
            spaceAfter=24
        )
        
        heading1_style = ParagraphStyle(
            'Heading1',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=24
        )
        
        normal_style = ParagraphStyle(
            'Normal',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=12
        )
        
        # Build document content
        content = []
        
        # Add title
        content.append(Paragraph(title, title_style))
        
        # Add date and author
        content.append(Paragraph(f"Date: {report_date}", normal_style))
        content.append(Paragraph(f"Author: {identity['personal']['full_name']}", normal_style))
        content.append(Paragraph(f"Position: {identity['personal'].get('job_title', 'Analyst')}", normal_style))
        content.append(Paragraph(f"Organization: {identity['employment'].get('company', 'Company, Inc.')}", normal_style))
        content.append(Spacer(1, 24))
        
        # Add table of contents header
        content.append(Paragraph("Table of Contents", heading1_style))
        
        # Add table of contents entries
        for i, section in enumerate(sections):
            content.append(Paragraph(f"{i+1}. {section['title']}", normal_style))
        
        content.append(PageBreak())
        
        # Add sections
        for i, section in enumerate(sections):
            content.append(Paragraph(f"{i+1}. {section['title']}", heading1_style))
            
            for paragraph in section['content']:
                content.append(Paragraph(paragraph, normal_style))
        
        # Add conclusion if not already included
        if not any("conclusion" in section['title'].lower() for section in sections):
            content.append(Paragraph("Conclusion", heading1_style))
            content.append(Paragraph(self.fake.paragraph(nb_sentences=random.randint(3, 5)), normal_style))
        
        # Build and save the document
        doc.build(content)
        
        console.print(f"[bold green]Report generated and saved to:[/] [bold]{output_file}[/]")
        return output_file
    
    def generate_invoice(self, identity=None, client=None, items=None, output_file=None):
        """Generate a professional-looking invoice document."""
        console.print(f"[bold blue]Generating invoice document[/]")
        
        # Generate seller if not provided
        if not identity:
            identity = {
                "personal": {
                    "full_name": self.fake.name()
                },
                "contact": {
                    "email": self.fake.email(),
                    "phone": self.fake.phone_number()
                },
                "employment": {
                    "company": self.fake.company()
                },
                "address": {
                    "street": self.fake.street_address(),
                    "city": self.fake.city(),
                    "state": self.fake.state_abbr(),
                    "zipcode": self.fake.zipcode()
                }
            }
        
        # Generate client if not provided
        if not client:
            client = {
                "name": self.fake.company(),
                "contact_person": self.fake.name(),
                "email": self.fake.email(),
                "phone": self.fake.phone_number(),
                "address": {
                    "street": self.fake.street_address(),
                    "city": self.fake.city(),
                    "state": self.fake.state_abbr(),
                    "zipcode": self.fake.zipcode()
                }
            }
        
        # Generate items if not provided
        if not items:
            items = []
            item_count = random.randint(3, 8)
            
            for i in range(item_count):
                items.append({
                    "description": self.fake.bs(),
                    "quantity": random.randint(1, 10),
                    "unit_price": round(random.uniform(10, 500), 2),
                    "tax_rate": random.choice([0, 0.05, 0.07, 0.1])
                })
        
        # Calculate totals
        subtotal = sum(item["quantity"] * item["unit_price"] for item in items)
        tax_total = sum(item["quantity"] * item["unit_price"] * item["tax_rate"] for item in items)
        total = subtotal + tax_total
        
        # Generate invoice details
        invoice_number = f"INV-{random.randint(10000, 99999)}"
        invoice_date = datetime.date.today().strftime("%Y-%m-%d")
        due_date = (datetime.date.today() + datetime.timedelta(days=30)).strftime("%Y-%m-%d")
        
        # Determine output file if not provided
        if not output_file:
            output_file = f"invoice_{invoice_number}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Create custom styles
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Title'],
            fontSize=18,
            spaceAfter=24
        )
        
        heading_style = ParagraphStyle(
            'Heading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=18
        )
        
        normal_style = ParagraphStyle(
            'Normal',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=6
        )
        
        # Build document content
        content = []
        
        # Add invoice header
        content.append(Paragraph("INVOICE", title_style))
        content.append(Paragraph(f"Invoice #: {invoice_number}", normal_style))
        content.append(Paragraph(f"Date: {invoice_date}", normal_style))
        content.append(Paragraph(f"Due Date: {due_date}", normal_style))
        content.append(Spacer(1, 12))
        
        # Add from/to addresses
        data = [
            ["FROM:", "TO:"],
            [
                f"{identity['employment'].get('company', 'Company, Inc.')}\n" +
                f"{identity['personal']['full_name']}\n" +
                f"{identity['address']['street']}\n" +
                f"{identity['address']['city']}, {identity['address']['state']} {identity['address']['zipcode']}\n" +
                f"Phone: {identity['contact']['phone']}\n" +
                f"Email: {identity['contact']['email']}",
                
                f"{client['name']}\n" +
                f"{client['contact_person']}\n" +
                f"{client['address']['street']}\n" +
                f"{client['address']['city']}, {client['address']['state']} {client['address']['zipcode']}\n" +
                f"Phone: {client['phone']}\n" +
                f"Email: {client['email']}"
            ]
        ]
        
        address_table = PDFTable(data, colWidths=[2.5*inch, 2.5*inch])
        address_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.gray),
            ('FONTSIZE', (0, 0), (1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (1, 0), 6),
        ]))
        
        content.append(address_table)
        content.append(Spacer(1, 24))
        
        # Add items table
        content.append(Paragraph("Items", heading_style))
        
        # Create items table
        item_data = [["Description", "Quantity", "Unit Price", "Tax Rate", "Amount"]]
        
        for item in items:
            amount = item["quantity"] * item["unit_price"]
            item_data.append([
                item["description"],
                str(item["quantity"]),
                f"${item['unit_price']:.2f}",
                f"{item['tax_rate']*100:.1f}%",
                f"${amount:.2f}"
            ])
        
        # Add totals
        item_data.append(["", "", "", "Subtotal:", f"${subtotal:.2f}"])
        item_data.append(["", "", "", "Tax:", f"${tax_total:.2f}"])
        item_data.append(["", "", "", "Total:", f"${total:.2f}"])
        
        items_table = PDFTable(item_data, colWidths=[3*inch, 0.75*inch, 1*inch, 0.75*inch, 1*inch])
        items_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -4), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -4), colors.black),
            ('ALIGN', (1, 1), (-1, -4), 'RIGHT'),
            ('FONTNAME', (0, 1), (-1, -4), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -4), 10),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -4), 0.25, colors.grey),
            ('ALIGN', (3, -3), (-1, -1), 'RIGHT'),
            ('FONTNAME', (3, -3), (-1, -1), 'Helvetica-Bold'),
            ('TOPPADDING', (3, -3), (-1, -1), 6),
            ('BOTTOMPADDING', (3, -3), (-1, -1), 6),
            ('LINEABOVE', (3, -3), (-1, -3), 1, colors.black),
        ]))
        
        content.append(items_table)
        content.append(Spacer(1, 36))
        
        # Add payment information
        content.append(Paragraph("Payment Information", heading_style))
        content.append(Paragraph("Please make payment by the due date to:", normal_style))
        content.append(Paragraph(f"Bank: {self.fake.company()} Bank", normal_style))
        content.append(Paragraph(f"Account Name: {identity['employment'].get('company', 'Company, Inc.')}", normal_style))
        content.append(Paragraph(f"Account Number: {self.fake.bban()}", normal_style))
        content.append(Paragraph(f"Routing Number: {self.fake.iban()}", normal_style))
        
        # Add terms and conditions
        content.append(Paragraph("Terms and Conditions", heading_style))
        content.append(Paragraph("1. Payment is due within 30 days of invoice date.", normal_style))
        content.append(Paragraph("2. Late payments are subject to a 1.5% monthly interest charge.", normal_style))
        content.append(Paragraph("3. Please include the invoice number with your payment.", normal_style))
        
        # Build and save the document
        doc.build(content)
        
        console.print(f"[bold green]Invoice generated and saved to:[/] [bold]{output_file}[/]")
        return output_file
    
    def generate_id_card(self, identity=None, id_type="generic", output_file=None):
        """Generate a fake identification card image."""
        console.print(f"[bold blue]Generating {id_type} ID card[/]")
        
        # Generate identity if not provided
        if not identity:
            fake = self.fake
            identity = {
                "personal": {
                    "prefix": random.choice(["Mr.", "Ms.", "Mrs.", ""]),
                    "first_name": fake.first_name(),
                    "middle_initial": random.choice(string.ascii_uppercase) + ".",
                    "last_name": fake.last_name(),
                    "gender": random.choice(["M", "F"]),
                    "birthdate": fake.date_of_birth(minimum_age=18, maximum_age=80).strftime("%Y-%m-%d")
                },
                "address": {
                    "street": fake.street_address(),
                    "city": fake.city(),
                    "state": fake.state_abbr(),
                    "zipcode": fake.zipcode()
                },
                "identification": {
                    "drivers_license": f"{random.choice(string.ascii_uppercase)}{random.randint(1000000, 9999999)}",
                    "passport": f"{random.choice(string.ascii_uppercase)}{random.randint(10000000, 99999999)}"
                },
                "physical": {
                    "height_cm": random.randint(150, 200),
                    "weight_kg": random.randint(50, 100),
                    "eye_color": random.choice(["BRN", "BLU", "GRN", "HAZ", "GRY"]),
                    "hair_color": random.choice(["BLK", "BRN", "BLN", "RED", "GRY", "WHT"])
                }
            }
        
        # Calculate age
        birth_date = datetime.datetime.strptime(identity["personal"]["birthdate"], "%Y-%m-%d").date()
        today = datetime.date.today()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        
        # Determine output file if not provided
        if not output_file:
            output_file = f"{id_type}_id_{identity['personal']['last_name'].lower()}.png"
        
        # Create ID card based on type
        if id_type.lower() == "drivers_license":
            # Create driver's license
            img = PILImage.new('RGB', (600, 375), color=(255, 255, 255))
            d = ImageDraw.Draw(img)
            
            # Try to load fonts, use default if not available
            try:
                title_font = ImageFont.truetype("Arial Bold.ttf", 24)
                header_font = ImageFont.truetype("Arial Bold.ttf", 16)
                normal_font = ImageFont.truetype("Arial.ttf", 14)
            except IOError:
                title_font = ImageFont.load_default()
                header_font = ImageFont.load_default()
                normal_font = ImageFont.load_default()
            
            # Add background color and border
            d.rectangle([(0, 0), (600, 375)], fill=(230, 230, 250))
            d.rectangle([(10, 10), (590, 365)], fill=(255, 255, 255), outline=(0, 0, 0), width=2)
            
            # Add title
            state = identity["address"]["state"]
            d.text((20, 20), f"{state} DRIVER LICENSE", font=title_font, fill=(0, 0, 128))
            
            # Add photo placeholder
            d.rectangle([(450, 60), (570, 180)], fill=(200, 200, 200), outline=(0, 0, 0))
            d.text((480, 110), "PHOTO", font=normal_font, fill=(100, 100, 100))
            
            # Add personal information
            y_pos = 60
            d.text((20, y_pos), "DL:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), identity["identification"]["drivers_license"], font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((20, y_pos), "NAME:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), f"{identity['personal']['last_name']}, {identity['personal']['first_name']} {identity['personal']['middle_initial']}", font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((20, y_pos), "ADDRESS:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), identity["address"]["street"], font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((100, y_pos), f"{identity['address']['city']}, {identity['address']['state']} {identity['address']['zipcode']}", font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((20, y_pos), "DOB:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), birth_date.strftime("%m/%d/%Y"), font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((20, y_pos), "SEX:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), identity["personal"]["gender"], font=normal_font, fill=(0, 0, 0))
            
            d.text((150, y_pos), "HGT:", font=header_font, fill=(0, 0, 0))
            height_ft = int(identity["physical"]["height_cm"] * 0.0328084)
            height_in = int((identity["physical"]["height_cm"] * 0.0328084 - height_ft) * 12)
            d.text((200, y_pos), f"{height_ft}'{height_in}\"", font=normal_font, fill=(0, 0, 0))
            
            d.text((250, y_pos), "WGT:", font=header_font, fill=(0, 0, 0))
            weight_lbs = int(identity["physical"]["weight_kg"] * 2.20462)
            d.text((300, y_pos), f"{weight_lbs} lbs", font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((20, y_pos), "EYES:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), identity["physical"]["eye_color"], font=normal_font, fill=(0, 0, 0))
            
            d.text((150, y_pos), "HAIR:", font=header_font, fill=(0, 0, 0))
            d.text((200, y_pos), identity["physical"]["hair_color"], font=normal_font, fill=(0, 0, 0))
            
            # Add issue and expiration dates
            issue_date = today - datetime.timedelta(days=random.randint(1, 365*4))
            exp_date = issue_date.replace(year=issue_date.year + 5)
            
            y_pos += 25
            d.text((20, y_pos), "ISSUED:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), issue_date.strftime("%m/%d/%Y"), font=normal_font, fill=(0, 0, 0))
            
            d.text((250, y_pos), "EXPIRES:", font=header_font, fill=(0, 0, 0))
            d.text((330, y_pos), exp_date.strftime("%m/%d/%Y"), font=normal_font, fill=(0, 0, 0))
            
            # Add signature placeholder
            y_pos += 40
            d.line([(20, y_pos), (400, y_pos)], fill=(0, 0, 0), width=1)
            d.text((150, y_pos + 5), "SIGNATURE", font=normal_font, fill=(100, 100, 100))
            
            # Add barcode placeholder
            d.rectangle([(20, 300), (570, 350)], fill=(240, 240, 240), outline=(0, 0, 0))
            d.text((270, 320), "BARCODE", font=normal_font, fill=(100, 100, 100))
            
        elif id_type.lower() == "passport":
            # Create passport
            img = PILImage.new('RGB', (600, 400), color=(0, 32, 91))
            d = ImageDraw.Draw(img)
            
            # Try to load fonts, use default if not available
            try:
                title_font = ImageFont.truetype("Arial Bold.ttf", 24)
                header_font = ImageFont.truetype("Arial Bold.ttf", 16)
                normal_font = ImageFont.truetype("Arial.ttf", 14)
            except IOError:
                title_font = ImageFont.load_default()
                header_font = ImageFont.load_default()
                normal_font = ImageFont.load_default()
            
            # Add inner border
            d.rectangle([(20, 20), (580, 380)], fill=(255, 255, 255), outline=(0, 0, 0), width=2)
            
            # Add title
            d.text((30, 30), "UNITED STATES OF AMERICA", font=title_font, fill=(0, 0, 128))
            d.text((30, 60), "PASSPORT", font=title_font, fill=(0, 0, 128))
            
            # Add photo placeholder
            d.rectangle([(400, 100), (550, 250)], fill=(200, 200, 200), outline=(0, 0, 0))
            d.text((450, 170), "PHOTO", font=normal_font, fill=(100, 100, 100))
            
            # Add passport information
            y_pos = 100
            d.text((30, y_pos), "Passport No:", font=header_font, fill=(0, 0, 0))
            d.text((150, y_pos), identity["identification"]["passport"], font=normal_font, fill=(0, 0, 0))
            
            y_pos += 30
            d.text((30, y_pos), "Surname:", font=header_font, fill=(0, 0, 0))
            d.text((150, y_pos), identity["personal"]["last_name"], font=normal_font, fill=(0, 0, 0))
            
            y_pos += 30
            d.text((30, y_pos), "Given Names:", font=header_font, fill=(0, 0, 0))
            d.text((150, y_pos), f"{identity['personal']['first_name']} {identity['personal']['middle_initial']}", font=normal_font, fill=(0, 0, 0))
            
            y_pos += 30
            d.text((30, y_pos), "Nationality:", font=header_font, fill=(0, 0, 0))
            d.text((150, y_pos), "UNITED STATES OF AMERICA", font=normal_font, fill=(0, 0, 0))
            
            y_pos += 30
            d.text((30, y_pos), "Date of Birth:", font=header_font, fill=(0, 0, 0))
            d.text((150, y_pos), birth_date.strftime("%d %b %Y"), font=normal_font, fill=(0, 0, 0))
            
            y_pos += 30
            d.text((30, y_pos), "Place of Birth:", font=header_font, fill=(0, 0, 0))
            d.text((150, y_pos), f"{identity['address']['city']}, {identity['address']['state']}, USA", font=normal_font, fill=(0, 0, 0))
            
            y_pos += 30
            d.text((30, y_pos), "Sex:", font=header_font, fill=(0, 0, 0))
            d.text((150, y_pos), "Male" if identity["personal"]["gender"] == "M" else "Female", font=normal_font, fill=(0, 0, 0))
            
            # Add issue and expiration dates
            issue_date = today - datetime.timedelta(days=random.randint(1, 365*4))
            exp_date = issue_date.replace(year=issue_date.year + 10)
            
            y_pos += 30
            d.text((30, y_pos), "Date of Issue:", font=header_font, fill=(0, 0, 0))
            d.text((150, y_pos), issue_date.strftime("%d %b %Y"), font=normal_font, fill=(0, 0, 0))
            
            y_pos += 30
            d.text((30, y_pos), "Date of Expiry:", font=header_font, fill=(0, 0, 0))
            d.text((150, y_pos), exp_date.strftime("%d %b %Y"), font=normal_font, fill=(0, 0, 0))
            
            # Add machine readable zone
            d.rectangle([(30, 330), (570, 370)], fill=(255, 255, 255), outline=(0, 0, 0))
            
            # First line: P<USA + surname + given names
            mrz_line1 = f"P<USA{identity['personal']['last_name']}"
            mrz_line1 = mrz_line1.ljust(44, '<')
            
            # Second line: Passport number + nationality + birth date + gender + expiry date + personal number
            mrz_line2 = (f"{identity['identification']['passport']}USA{birth_date.strftime('%y%m%d')}"
                         f"{'M' if identity['personal']['gender'] == 'M' else 'F'}{exp_date.strftime('%y%m%d')}")
            mrz_line2 = mrz_line2.ljust(44, '<')
            
            d.text((40, 340), mrz_line1, font=normal_font, fill=(0, 0, 0))
            d.text((40, 355), mrz_line2, font=normal_font, fill=(0, 0, 0))
            
        else:
            # Create generic ID card
            img = PILImage.new('RGB', (600, 375), color=(240, 240, 240))
            d = ImageDraw.Draw(img)
            
            # Try to load fonts, use default if not available
            try:
                title_font = ImageFont.truetype("Arial Bold.ttf", 24)
                header_font = ImageFont.truetype("Arial Bold.ttf", 16)
                normal_font = ImageFont.truetype("Arial.ttf", 14)
            except IOError:
                title_font = ImageFont.load_default()
                header_font = ImageFont.load_default()
                normal_font = ImageFont.load_default()
            
            # Add border
            d.rectangle([(0, 0), (600, 375)], fill=(240, 240, 240), outline=(0, 0, 0), width=2)
            
            # Add title
            d.text((20, 20), "IDENTIFICATION CARD", font=title_font, fill=(0, 0, 0))
            
            # Add photo placeholder
            d.rectangle([(450, 60), (570, 180)], fill=(200, 200, 200), outline=(0, 0, 0))
            d.text((480, 110), "PHOTO", font=normal_font, fill=(100, 100, 100))
            
            # Add personal information
            y_pos = 60
            d.text((20, y_pos), "ID:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), f"ID-{random.randint(100000, 999999)}", font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((20, y_pos), "NAME:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), f"{identity['personal']['first_name']} {identity['personal']['middle_initial']} {identity['personal']['last_name']}", font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((20, y_pos), "ADDRESS:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), identity["address"]["street"], font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((100, y_pos), f"{identity['address']['city']}, {identity['address']['state']} {identity['address']['zipcode']}", font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((20, y_pos), "DOB:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), birth_date.strftime("%m/%d/%Y"), font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((20, y_pos), "SEX:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), identity["personal"]["gender"], font=normal_font, fill=(0, 0, 0))
            
            # Add issue and expiration dates
            issue_date = today - datetime.timedelta(days=random.randint(1, 365*2))
            exp_date = issue_date.replace(year=issue_date.year + 4)
            
            y_pos += 25
            d.text((20, y_pos), "ISSUED:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), issue_date.strftime("%m/%d/%Y"), font=normal_font, fill=(0, 0, 0))
            
            y_pos += 25
            d.text((20, y_pos), "EXPIRES:", font=header_font, fill=(0, 0, 0))
            d.text((100, y_pos), exp_date.strftime("%m/%d/%Y"), font=normal_font, fill=(0, 0, 0))
            
            # Add signature placeholder
            y_pos += 40
            d.line([(20, y_pos), (400, y_pos)], fill=(0, 0, 0), width=1)
            d.text((150, y_pos + 5), "SIGNATURE", font=normal_font, fill=(100, 100, 100))
            
            # Add barcode placeholder
            d.rectangle([(20, 300), (570, 350)], fill=(240, 240, 240), outline=(0, 0, 0))
            d.text((270, 320), "BARCODE", font=normal_font, fill=(100, 100, 100))
        
        # Save the image
        img.save(output_file)
        
        console.print(f"[bold green]ID card generated and saved to:[/] [bold]{output_file}[/]")
        return output_file
    
    def generate_document(self, document_type, identity=None, output_file=None):
        """Generate a document of the specified type."""
        console.print(f"[bold blue]Generating {document_type} document[/]")
        
        # Validate document type
        if document_type not in self.document_types:
            console.print(f"[bold red]Error:[/] Unknown document type: {document_type}")
            console.print(f"[bold yellow]Available types:[/] {', '.join(self.document_types)}")
            return None
        
        # Generate identity if not provided
        if not identity:
            fake = self.fake
            identity = {
                "personal": {
                    "prefix": random.choice(["Mr.", "Ms.", "Mrs.", ""]),
                    "first_name": fake.first_name(),
                    "middle_initial": random.choice(string.ascii_uppercase) + ".",
                    "last_name": fake.last_name(),
                    "full_name": "",
                    "gender": random.choice(["M", "F"]),
                    "birthdate": fake.date_of_birth(minimum_age=18, maximum_age=80).strftime("%Y-%m-%d")
                },
                "address": {
                    "street": fake.street_address(),
                    "city": fake.city(),
                    "state": fake.state_abbr(),
                    "zipcode": fake.zipcode()
                },
                "contact": {
                    "email": fake.email(),
                    "phone": fake.phone_number()
                },
                "employment": {
                    "company": fake.company(),
                    "job_title": fake.job()
                },
                "identification": {
                    "drivers_license": f"{random.choice(string.ascii_uppercase)}{random.randint(1000000, 9999999)}",
                    "passport": f"{random.choice(string.ascii_uppercase)}{random.randint(10000000, 99999999)}"
                }
            }
            
            # Set full name
            identity["personal"]["full_name"] = (f"{identity['personal']['prefix']} "
                                               f"{identity['personal']['first_name']} "
                                               f"{identity['personal']['middle_initial']} "
                                               f"{identity['personal']['last_name']}").strip()
        
        # Generate document based on type
        if document_type == "report":
            return self.generate_report(identity=identity, output_file=output_file)
        elif document_type == "invoice":
            return self.generate_invoice(identity=identity, output_file=output_file)
        elif document_type in ["id_card", "drivers_license", "passport"]:
            return self.generate_id_card(identity=identity, id_type=document_type, output_file=output_file)
        else:
            console.print(f"[bold yellow]Warning:[/] Document type '{document_type}' not yet implemented")
            return None
    
    def generate_multiple_documents(self, document_types, identity=None, output_dir=None):
        """Generate multiple documents for the same identity."""
        console.print(f"[bold blue]Generating multiple documents[/]")
        
        # Generate identity if not provided
        if not identity:
            fake = self.fake
            identity = {
                "personal": {
                    "prefix": random.choice(["Mr.", "Ms.", "Mrs.", ""]),
                    "first_name": fake.first_name(),
                    "middle_initial": random.choice(string.ascii_uppercase) + ".",
                    "last_name": fake.last_name(),
                    "full_name": "",
                    "gender": random.choice(["M", "F"]),
                    "birthdate": fake.date_of_birth(minimum_age=18, maximum_age=80).strftime("%Y-%m-%d")
                },
                "address": {
                    "street": fake.street_address(),
                    "city": fake.city(),
                    "state": fake.state_abbr(),
                    "zipcode": fake.zipcode()
                },
                "contact": {
                    "email": fake.email(),
                    "phone": fake.phone_number()
                },
                "employment": {
                    "company": fake.company(),
                    "job_title": fake.job()
                },
                "identification": {
                    "drivers_license": f"{random.choice(string.ascii_uppercase)}{random.randint(1000000, 9999999)}",
                    "passport": f"{random.choice(string.ascii_uppercase)}{random.randint(10000000, 99999999)}"
                }
            }
            
            # Set full name
            identity["personal"]["full_name"] = (f"{identity['personal']['prefix']} "
                                               f"{identity['personal']['first_name']} "
                                               f"{identity['personal']['middle_initial']} "
                                               f"{identity['personal']['last_name']}").strip()
        
        # Create output directory if not provided
        if not output_dir:
            output_dir = f"documents_{identity['personal']['last_name'].lower()}"
        
        # Create directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate documents
        generated_files = []
        
        for doc_type in document_types:
            output_file = os.path.join(output_dir, f"{doc_type}_{identity['personal']['last_name'].lower()}")
            
            # Add appropriate extension
            if doc_type in ["id_card", "drivers_license", "passport"]:
                output_file += ".png"
            else:
                output_file += ".pdf"
            
            # Generate document
            result = self.generate_document(doc_type, identity=identity, output_file=output_file)
            
            if result:
                generated_files.append(result)
        
        console.print(f"[bold green]Generated {len(generated_files)} documents in:[/] [bold]{output_dir}[/]")
        return generated_files
