"""
Report Generator module for the Ultimate PI Tool.

This module provides functionality for generating comprehensive reports
based on collected data from various sources.
"""

import os
import sys
import json
import datetime
from rich.console import Console
from rich.table import Table
from fpdf import FPDF

console = Console()

class ReportGenerator:
    """Report Generator class for creating comprehensive investigation reports."""
    
    def __init__(self):
        """Initialize the Report Generator module."""
        self.templates_dir = os.path.expanduser("~/.pi_tool_templates")
        self.ensure_templates_dir()
    
    def generate_report(self, subject, output_file=None, template=None, data=None):
        """Generate a comprehensive report for a subject."""
        console.print(f"[bold blue]Generating report for:[/] [bold green]{subject}[/]")
        
        try:
            # Determine output file
            if not output_file:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"report_{subject.replace(' ', '_')}_{timestamp}.pdf"
            
            # Load template if specified
            template_data = None
            if template:
                template_path = os.path.join(self.templates_dir, f"{template}.json")
                if os.path.exists(template_path):
                    with open(template_path, 'r') as f:
                        template_data = json.load(f)
                else:
                    console.print(f"[bold yellow]Warning:[/] Template '{template}' not found. Using default template.")
            
            # Use default template if none specified or not found
            if not template_data:
                template_data = self._get_default_template()
            
            # Load data if specified
            report_data = {}
            if data and os.path.exists(data):
                with open(data, 'r') as f:
                    report_data = json.load(f)
            
            # Generate the report
            self._generate_pdf_report(subject, output_file, template_data, report_data)
            
            console.print(f"[bold green]Report generated and saved to:[/] [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def create_template(self, name, output_file=None):
        """Create a new report template."""
        console.print(f"[bold blue]Creating report template:[/] [bold green]{name}[/]")
        
        try:
            # Determine output file
            if not output_file:
                output_file = os.path.join(self.templates_dir, f"{name}.json")
            
            # Check if template already exists
            if os.path.exists(output_file):
                console.print(f"[bold yellow]Warning:[/] Template '{name}' already exists. Please choose a different name or delete the existing template.")
                return False
            
            # Create template structure
            template = {
                "name": name,
                "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "sections": [
                    {
                        "title": "Executive Summary",
                        "content": "This section provides a high-level overview of the investigation findings.",
                        "order": 1
                    },
                    {
                        "title": "Subject Information",
                        "content": "This section contains basic information about the subject of the investigation.",
                        "order": 2
                    },
                    {
                        "title": "Investigation Methodology",
                        "content": "This section describes the methods and tools used in the investigation.",
                        "order": 3
                    },
                    {
                        "title": "Findings",
                        "content": "This section presents the detailed findings of the investigation.",
                        "order": 4
                    },
                    {
                        "title": "Evidence",
                        "content": "This section lists and describes the evidence collected during the investigation.",
                        "order": 5
                    },
                    {
                        "title": "Conclusions",
                        "content": "This section presents the conclusions drawn from the investigation findings.",
                        "order": 6
                    },
                    {
                        "title": "Recommendations",
                        "content": "This section provides recommendations based on the investigation findings.",
                        "order": 7
                    },
                    {
                        "title": "Appendices",
                        "content": "This section contains additional information and supporting documentation.",
                        "order": 8
                    }
                ],
                "header": {
                    "include_logo": True,
                    "include_date": True,
                    "include_page_number": True,
                    "title": "Investigation Report"
                },
                "footer": {
                    "include_confidentiality_notice": True,
                    "include_page_number": True,
                    "text": "Confidential - For authorized use only"
                },
                "styling": {
                    "font_family": "Arial",
                    "title_font_size": 16,
                    "heading_font_size": 12,
                    "body_font_size": 10,
                    "line_spacing": 1.5,
                    "page_margin": 20
                }
            }
            
            # Save template
            with open(output_file, 'w') as f:
                json.dump(template, f, indent=2)
            
            console.print(f"[bold green]Template created and saved to:[/] [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def list_templates(self):
        """List available report templates."""
        console.print("[bold blue]Available report templates:[/]")
        
        try:
            # Ensure templates directory exists
            self.ensure_templates_dir()
            
            # Get list of template files
            templates = []
            for filename in os.listdir(self.templates_dir):
                if filename.endswith('.json'):
                    template_path = os.path.join(self.templates_dir, filename)
                    with open(template_path, 'r') as f:
                        template_data = json.load(f)
                    
                    templates.append({
                        'name': template_data.get('name', os.path.splitext(filename)[0]),
                        'created': template_data.get('created', 'Unknown'),
                        'sections': len(template_data.get('sections', [])),
                        'file': filename
                    })
            
            if templates:
                # Create table for display
                table = Table(title="Report Templates")
                table.add_column("Name", style="cyan")
                table.add_column("Created", style="green")
                table.add_column("Sections", style="yellow")
                table.add_column("File", style="magenta")
                
                for template in templates:
                    table.add_row(
                        template['name'],
                        template['created'],
                        str(template['sections']),
                        template['file']
                    )
                
                console.print(table)
            else:
                console.print("[bold yellow]No templates found.[/]")
            
            return templates
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def delete_template(self, name):
        """Delete a report template."""
        console.print(f"[bold blue]Deleting report template:[/] [bold green]{name}[/]")
        
        try:
            # Determine template file
            template_path = os.path.join(self.templates_dir, f"{name}.json")
            
            # Check if template exists
            if not os.path.exists(template_path):
                console.print(f"[bold yellow]Warning:[/] Template '{name}' not found.")
                return False
            
            # Delete template
            os.remove(template_path)
            
            console.print(f"[bold green]Template '{name}' deleted.[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def ensure_templates_dir(self):
        """Ensure templates directory exists."""
        if not os.path.exists(self.templates_dir):
            os.makedirs(self.templates_dir)
            console.print(f"[bold blue]Created templates directory:[/] [bold]{self.templates_dir}[/]")
    
    def _get_default_template(self):
        """Get the default report template."""
        return {
            "name": "Default",
            "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sections": [
                {
                    "title": "Executive Summary",
                    "content": "This section provides a high-level overview of the investigation findings.",
                    "order": 1
                },
                {
                    "title": "Subject Information",
                    "content": "This section contains basic information about the subject of the investigation.",
                    "order": 2
                },
                {
                    "title": "Investigation Methodology",
                    "content": "This section describes the methods and tools used in the investigation.",
                    "order": 3
                },
                {
                    "title": "Findings",
                    "content": "This section presents the detailed findings of the investigation.",
                    "order": 4
                },
                {
                    "title": "Conclusions",
                    "content": "This section presents the conclusions drawn from the investigation findings.",
                    "order": 5
                },
                {
                    "title": "Recommendations",
                    "content": "This section provides recommendations based on the investigation findings.",
                    "order": 6
                }
            ],
            "header": {
                "include_logo": True,
                "include_date": True,
                "include_page_number": True,
                "title": "Investigation Report"
            },
            "footer": {
                "include_confidentiality_notice": True,
                "include_page_number": True,
                "text": "Confidential - For authorized use only"
            },
            "styling": {
                "font_family": "Arial",
                "title_font_size": 16,
                "heading_font_size": 12,
                "body_font_size": 10,
                "line_spacing": 1.5,
                "page_margin": 20
            }
        }
    
    def _generate_pdf_report(self, subject, output_file, template, data):
        """Generate a PDF report using the specified template and data."""
        # Create PDF object
        pdf = FPDF()
        
        # Set document properties
        pdf.set_title(f"Investigation Report - {subject}")
        pdf.set_author("Ultimate PI Tool")
        pdf.set_creator("Ultimate PI Tool Report Generator")
        
        # Get styling from template
        styling = template.get('styling', {})
        font_family = styling.get('font_family', 'Arial')
        title_font_size = styling.get('title_font_size', 16)
        heading_font_size = styling.get('heading_font_size', 12)
        body_font_size = styling.get('body_font_size', 10)
        line_spacing = styling.get('line_spacing', 1.5)
        page_margin = styling.get('page_margin', 20)
        
        # Set margins
        pdf.set_margins(page_margin, page_margin, page_margin)
        
        # Add cover page
        pdf.add_page()
        
        # Set font for title
        pdf.set_font(font_family, 'B', title_font_size)
        
        # Add title
        header = template.get('header', {})
        report_title = header.get('title', 'Investigation Report')
        pdf.cell(0, 20, report_title, 0, 1, 'C')
        
        # Add subject
        pdf.set_font(font_family, 'B', heading_font_size)
        pdf.cell(0, 10, f"Subject: {subject}", 0, 1, 'C')
        
        # Add date
        if header.get('include_date', True):
            pdf.set_font(font_family, '', body_font_size)
            pdf.cell(0, 10, f"Date: {datetime.datetime.now().strftime('%Y-%m-%d')}", 0, 1, 'C')
        
        # Add prepared by
        pdf.set_font(font_family, '', body_font_size)
        pdf.cell(0, 10, "Prepared by: Ultimate PI Tool", 0, 1, 'C')
        
        # Add confidentiality notice
        footer = template.get('footer', {})
        if footer.get('include_confidentiality_notice', True):
            pdf.ln(20)
            pdf.set_font(font_family, 'I', body_font_size)
            pdf.cell(0, 10, footer.get('text', 'Confidential - For authorized use only'), 0, 1, 'C')
        
        # Add sections
        sections = sorted(template.get('sections', []), key=lambda x: x.get('order', 999))
        
        for section in sections:
            pdf.add_page()
            
            # Add section title
            pdf.set_font(font_family, 'B', heading_font_size)
            pdf.cell(0, 10, section.get('title', 'Section'), 0, 1, 'L')
            pdf.ln(5)
            
            # Add section content
            pdf.set_font(font_family, '', body_font_size)
            
            # Get content from data if available, otherwise use template content
            section_title = section.get('title', '').lower().replace(' ', '_')
            content = data.get(section_title, section.get('content', ''))
            
            # Split content into lines and add to PDF
            lines = content.split('\n')
            for line in lines:
                pdf.multi_cell(0, line_spacing * body_font_size, line)
                pdf.ln(3)
        
        # Save the PDF
        pdf.output(output_file)
