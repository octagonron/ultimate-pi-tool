"""
Timeline Analyzer module for the Ultimate PI Tool.

This module provides functionality for creating and analyzing timelines
of events for investigations.
"""

import os
import sys
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

console = Console()

class TimelineAnalyzer:
    """Timeline Analyzer class for creating and analyzing event timelines."""
    
    def __init__(self):
        """Initialize the Timeline Analyzer module."""
        pass
    
    def create_timeline(self, data_file, output_file=None):
        """Create a timeline from data."""
        console.print(f"[bold blue]Creating timeline from:[/] [bold green]{data_file}[/]")
        
        try:
            # Check if file exists
            if not os.path.exists(data_file):
                console.print(f"[bold red]Error:[/] Data file not found: {data_file}")
                return False
            
            # Load data
            data = self._load_data(data_file)
            
            if not data:
                console.print(f"[bold red]Error:[/] Failed to load data from: {data_file}")
                return False
            
            # Determine output file if not specified
            if not output_file:
                output_file = f"{os.path.splitext(data_file)[0]}_timeline.html"
            
            # Create timeline visualization
            timeline = self._create_timeline_visualization(data, output_file)
            
            console.print(f"[bold green]Timeline created and saved to:[/] [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def analyze_timeline(self, timeline_file):
        """Analyze a timeline for patterns and anomalies."""
        console.print(f"[bold blue]Analyzing timeline:[/] [bold green]{timeline_file}[/]")
        
        try:
            # Check if file exists
            if not os.path.exists(timeline_file):
                console.print(f"[bold red]Error:[/] Timeline file not found: {timeline_file}")
                return False
            
            # Load data
            data = self._load_data(timeline_file)
            
            if not data:
                console.print(f"[bold red]Error:[/] Failed to load data from: {timeline_file}")
                return False
            
            # Extract events
            events = self._extract_timeline_events(data)
            
            if not events:
                console.print(f"[bold red]Error:[/] No timeline events found in the data")
                return False
            
            # Analyze timeline
            analysis = self._analyze_timeline_events(events)
            
            # Display analysis results
            self._display_timeline_analysis(analysis)
            
            # Generate analysis report
            report_file = f"{os.path.splitext(timeline_file)[0]}_analysis.html"
            self._generate_timeline_analysis_report(analysis, report_file)
            
            console.print(f"[bold green]Timeline analysis complete. Report saved to:[/] [bold]{report_file}[/]")
            return analysis
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def merge_timelines(self, timeline_files, output_file=None):
        """Merge multiple timelines into a single timeline."""
        console.print(f"[bold blue]Merging {len(timeline_files)} timelines[/]")
        
        try:
            # Check if files exist
            all_events = []
            
            for timeline_file in timeline_files:
                if not os.path.exists(timeline_file):
                    console.print(f"[bold yellow]Warning:[/] Timeline file not found: {timeline_file}")
                    continue
                
                # Load data
                data = self._load_data(timeline_file)
                
                if not data:
                    console.print(f"[bold yellow]Warning:[/] Failed to load data from: {timeline_file}")
                    continue
                
                # Extract events
                events = self._extract_timeline_events(data)
                
                if events:
                    # Add source information to events
                    for event in events:
                        event['source'] = os.path.basename(timeline_file)
                    
                    all_events.extend(events)
            
            if not all_events:
                console.print(f"[bold red]Error:[/] No timeline events found in any of the files")
                return False
            
            # Determine output file if not specified
            if not output_file:
                output_file = "merged_timeline.html"
            
            # Create merged timeline visualization
            merged_timeline = self._create_merged_timeline_visualization(all_events, output_file)
            
            console.print(f"[bold green]Merged timeline created and saved to:[/] [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def find_gaps(self, timeline_file, threshold_hours=24):
        """Find gaps in a timeline."""
        console.print(f"[bold blue]Finding gaps in timeline:[/] [bold green]{timeline_file}[/]")
        
        try:
            # Check if file exists
            if not os.path.exists(timeline_file):
                console.print(f"[bold red]Error:[/] Timeline file not found: {timeline_file}")
                return False
            
            # Load data
            data = self._load_data(timeline_file)
            
            if not data:
                console.print(f"[bold red]Error:[/] Failed to load data from: {timeline_file}")
                return False
            
            # Extract events
            events = self._extract_timeline_events(data)
            
            if not events:
                console.print(f"[bold red]Error:[/] No timeline events found in the data")
                return False
            
            # Find gaps
            gaps = self._find_timeline_gaps(events, threshold_hours)
            
            # Display gaps
            self._display_timeline_gaps(gaps, threshold_hours)
            
            # Generate gaps report
            report_file = f"{os.path.splitext(timeline_file)[0]}_gaps.html"
            self._generate_timeline_gaps_report(events, gaps, report_file)
            
            console.print(f"[bold green]Timeline gap analysis complete. Report saved to:[/] [bold]{report_file}[/]")
            return gaps
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def create_comparative_timeline(self, timeline_files, output_file=None):
        """Create a comparative timeline from multiple sources."""
        console.print(f"[bold blue]Creating comparative timeline from {len(timeline_files)} sources[/]")
        
        try:
            # Check if files exist
            timelines = []
            
            for timeline_file in timeline_files:
                if not os.path.exists(timeline_file):
                    console.print(f"[bold yellow]Warning:[/] Timeline file not found: {timeline_file}")
                    continue
                
                # Load data
                data = self._load_data(timeline_file)
                
                if not data:
                    console.print(f"[bold yellow]Warning:[/] Failed to load data from: {timeline_file}")
                    continue
                
                # Extract events
                events = self._extract_timeline_events(data)
                
                if events:
                    source_name = os.path.basename(timeline_file)
                    timelines.append({
                        'source': source_name,
                        'events': events
                    })
            
            if not timelines:
                console.print(f"[bold red]Error:[/] No timeline events found in any of the files")
                return False
            
            # Determine output file if not specified
            if not output_file:
                output_file = "comparative_timeline.html"
            
            # Create comparative timeline visualization
            comparative_timeline = self._create_comparative_timeline_visualization(timelines, output_file)
            
            console.print(f"[bold green]Comparative timeline created and saved to:[/] [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def _load_data(self, data_file):
        """Load data from a file based on its extension."""
        try:
            # Get file extension
            _, ext = os.path.splitext(data_file)
            ext = ext.lower()
            
            # Load data based on extension
            if ext == '.json':
                with open(data_file, 'r') as f:
                    data = json.load(f)
            elif ext == '.csv':
                data = pd.read_csv(data_file).to_dict('records')
            elif ext == '.xlsx' or ext == '.xls':
                data = pd.read_excel(data_file).to_dict('records')
            else:
                console.print(f"[bold yellow]Warning:[/] Unsupported file format: {ext}")
                return None
            
            return data
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Failed to load data: {str(e)}")
            return None
    
    def _extract_timeline_events(self, data):
        """Extract timeline events from the dataset."""
        events = []
        
        try:
            # Check if data contains explicit timeline information
            if isinstance(data, dict) and 'events' in data:
                # Direct format with events
                return data['events']
            
            # Try to extract timeline events from records
            if isinstance(data, list):
                # Identify date fields
                date_fields = set()
                for record in data:
                    if isinstance(record, dict):
                        for key, value in record.items():
                            if isinstance(value, str) and self._looks_like_date(value):
                                date_fields.add(key)
                
                # If no date fields found, return empty list
                if not date_fields:
                    return []
                
                # Use the first date field found
                date_field = next(iter(date_fields))
                
                # Extract categories
                categories = set()
                for record in data:
                    if isinstance(record, dict) and 'category' in record:
                        categories.add(record['category'])
                
                # If no categories found, use a default category
                if not categories:
                    categories = {'Events'}
                
                # Create events
                for i, record in enumerate(data):
                    if isinstance(record, dict) and date_field in record:
                        date_value = record[date_field]
                        
                        # Skip if not a valid date
                        if not self._looks_like_date(date_value):
                            continue
                        
                        # Get category
                        category = record.get('category', next(iter(categories)))
                        
                        # Get title and description
                        title = record.get('title', record.get('name', f"Event {i+1}"))
                        
                        # Create description from record attributes
                        description = f"<b>{title}</b><br>"
                        for key, value in record.items():
                            if key not in ['id', 'title', 'name', 'category', date_field]:
                                description += f"{key}: {value}<br>"
                        
                        # Create event object
                        event = {
                            'id': record.get('id', f"event_{i}"),
                            'date': date_value,
                            'category': category,
                            'title': title,
                            'description': description,
                            'color': self._get_category_color(category),
                            'symbol': 'circle'
                        }
                        
                        events.append(event)
            
            # Sort events by date
            events.sort(key=lambda x: x['date'])
            
            return events
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Timeline event extraction error: {str(e)}")
            return []
    
    def _looks_like_date(self, value):
        """Check if a string looks like a date."""
        if not isinstance(value, str):
            return False
        
        # Check for common date formats
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'\d{2}/\d{2}/\d{4}',  # MM/DD/YYYY
            r'\d{2}-\d{2}-\d{4}',  # MM-DD-YYYY
            r'\d{4}/\d{2}/\d{2}'   # YYYY/MM/DD
        ]
        
        import re
        for pattern in date_patterns:
            if re.match(pattern, value):
                return True
        
        return False
    
    def _get_category_color(self, category):
        """Get a color for a category."""
        # Define a set of colors for different categories
        category_colors = {
            'Events': 'blue',
            'Communications': 'green',
            'Transactions': 'red',
            'Travel': 'purple',
            'Meetings': 'orange',
            'Documents': 'brown',
            'Legal': 'darkblue',
            'Financial': 'darkgreen'
        }
        
        # Return the color for the category, or a default color
        return category_colors.get(category, 'gray')
    
    def _create_timeline_visualization(self, data, output_file):
        """Create a timeline visualization."""
        try:
            # Extract timeline events
            events = self._extract_timeline_events(data)
            
            if not events:
                console.print(f"[bold yellow]Warning:[/] No timeline events found in the dataset")
                return False
            
            # Create a plotly figure
            fig = go.Figure()
            
            # Group events by category
            categories = {}
            for event in events:
                category = event['category']
                if category not in categories:
                    categories[category] = []
                categories[category].append(event)
            
            # Add events to the timeline by category
            for category, category_events in categories.items():
                # Extract dates and titles
                dates = [event['date'] for event in category_events]
                titles = [event['title'] for event in category_events]
                descriptions = [event['description'] for event in category_events]
                color = category_events[0]['color']  # All events in a category have the same color
                
                # Add category to the timeline
                fig.add_trace(go.Scatter(
                    x=dates,
                    y=[category] * len(dates),
                    mode='markers',
                    marker=dict(
                        size=15,
                        color=color,
                        symbol='circle',
                        line=dict(width=2, color='DarkSlateGrey')
                    ),
                    name=category,
                    text=descriptions,
                    hoverinfo='text'
                ))
            
            # Update layout
            fig.update_layout(
                title="Investigation Timeline",
                xaxis=dict(
                    title="Date",
                    showgrid=True,
                    zeroline=False,
                    showline=True,
                    showticklabels=True,
                    type='date'
                ),
                yaxis=dict(
                    title="Category",
                    showgrid=True,
                    zeroline=False,
                    showline=True,
                    showticklabels=True
                ),
                hovermode='closest',
                height=600,
                margin=dict(l=100, r=50, t=100, b=100),
                plot_bgcolor='rgba(240, 240, 240, 0.8)'
            )
            
            # Save the figure
            fig.write_html(output_file)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Timeline visualization error: {str(e)}")
            return False
    
    def _analyze_timeline_events(self, events):
        """Analyze timeline events for patterns and anomalies."""
        analysis = {
            'event_count': len(events),
            'date_range': {},
            'categories': {},
            'frequency': {},
            'gaps': [],
            'clusters': [],
            'anomalies': []
        }
        
        try:
            if not events:
                return analysis
            
            # Convert dates to datetime objects
            for event in events:
                event['datetime'] = self._parse_date(event['date'])
            
            # Sort events by date
            events.sort(key=lambda x: x['datetime'])
            
            # Calculate date range
            start_date = events[0]['datetime']
            end_date = events[-1]['datetime']
            duration = end_date - start_date
            
            analysis['date_range'] = {
                'start': start_date.strftime('%Y-%m-%d'),
                'end': end_date.strftime('%Y-%m-%d'),
                'duration_days': duration.days
            }
            
            # Analyze categories
            categories = {}
            for event in events:
                category = event['category']
                if category not in categories:
                    categories[category] = 0
                categories[category] += 1
            
            analysis['categories'] = categories
            
            # Analyze frequency
            if duration.days > 0:
                # Calculate events per day
                events_per_day = len(events) / duration.days
                
                # Calculate events per month
                events_per_month = len(events) / (duration.days / 30)
                
                analysis['frequency'] = {
                    'events_per_day': events_per_day,
                    'events_per_month': events_per_month
                }
            
            # Find gaps
            gaps = self._find_timeline_gaps(events, 7)  # Gaps of 7 days or more
            analysis['gaps'] = gaps
            
            # Find clusters
            clusters = self._find_timeline_clusters(events, 1)  # Clusters with events within 1 day
            analysis['clusters'] = clusters
            
            # Find anomalies
            anomalies = self._find_timeline_anomalies(events)
            analysis['anomalies'] = anomalies
            
            return analysis
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Timeline analysis error: {str(e)}")
            return analysis
    
    def _parse_date(self, date_string):
        """Parse a date string into a datetime object."""
        try:
            # Try different date formats
            formats = [
                '%Y-%m-%d',      # YYYY-MM-DD
                '%m/%d/%Y',      # MM/DD/YYYY
                '%d/%m/%Y',      # DD/MM/YYYY
                '%Y/%m/%d',      # YYYY/MM/DD
                '%m-%d-%Y',      # MM-DD-YYYY
                '%d-%m-%Y',      # DD-MM-YYYY
                '%Y-%m-%d %H:%M:%S',  # YYYY-MM-DD HH:MM:SS
                '%m/%d/%Y %H:%M:%S',  # MM/DD/YYYY HH:MM:SS
                '%d/%m/%Y %H:%M:%S',  # DD/MM/YYYY HH:MM:SS
                '%Y/%m/%d %H:%M:%S'   # YYYY/MM/DD HH:MM:SS
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(date_string, fmt)
                except ValueError:
                    continue
            
            # If all formats fail, raise an exception
            raise ValueError(f"Could not parse date: {date_string}")
            
        except Exception as e:
            # Return a default date if parsing fails
            console.print(f"[bold yellow]Warning:[/] Date parsing error for '{date_string}': {str(e)}")
            return datetime(2000, 1, 1)  # Default date
    
    def _find_timeline_gaps(self, events, threshold_days):
        """Find gaps in a timeline."""
        gaps = []
        
        try:
            if len(events) < 2:
                return gaps
            
            # Sort events by date
            sorted_events = sorted(events, key=lambda x: x['datetime'])
            
            # Find gaps
            for i in range(1, len(sorted_events)):
                prev_event = sorted_events[i-1]
                curr_event = sorted_events[i]
                
                # Calculate gap
                gap = curr_event['datetime'] - prev_event['datetime']
                
                # If gap is greater than threshold, add to gaps
                if gap.days >= threshold_days:
                    gaps.append({
                        'start_date': prev_event['datetime'].strftime('%Y-%m-%d'),
                        'end_date': curr_event['datetime'].strftime('%Y-%m-%d'),
                        'duration_days': gap.days,
                        'start_event': prev_event['title'],
                        'end_event': curr_event['title']
                    })
            
            return gaps
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Gap finding error: {str(e)}")
            return gaps
    
    def _find_timeline_clusters(self, events, threshold_days):
        """Find clusters of events in a timeline."""
        clusters = []
        
        try:
            if len(events) < 2:
                return clusters
            
            # Sort events by date
            sorted_events = sorted(events, key=lambda x: x['datetime'])
            
            # Initialize current cluster
            current_cluster = [sorted_events[0]]
            
            # Find clusters
            for i in range(1, len(sorted_events)):
                prev_event = sorted_events[i-1]
                curr_event = sorted_events[i]
                
                # Calculate gap
                gap = curr_event['datetime'] - prev_event['datetime']
                
                # If gap is less than or equal to threshold, add to current cluster
                if gap.days <= threshold_days:
                    current_cluster.append(curr_event)
                else:
                    # If cluster has at least 3 events, add to clusters
                    if len(current_cluster) >= 3:
                        clusters.append({
                            'start_date': current_cluster[0]['datetime'].strftime('%Y-%m-%d'),
                            'end_date': current_cluster[-1]['datetime'].strftime('%Y-%m-%d'),
                            'event_count': len(current_cluster),
                            'events': [event['title'] for event in current_cluster]
                        })
                    
                    # Start a new cluster
                    current_cluster = [curr_event]
            
            # Check if the last cluster has at least 3 events
            if len(current_cluster) >= 3:
                clusters.append({
                    'start_date': current_cluster[0]['datetime'].strftime('%Y-%m-%d'),
                    'end_date': current_cluster[-1]['datetime'].strftime('%Y-%m-%d'),
                    'event_count': len(current_cluster),
                    'events': [event['title'] for event in current_cluster]
                })
            
            return clusters
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Cluster finding error: {str(e)}")
            return clusters
    
    def _find_timeline_anomalies(self, events):
        """Find anomalies in a timeline."""
        anomalies = []
        
        try:
            if len(events) < 5:  # Need at least 5 events for meaningful anomaly detection
                return anomalies
            
            # Sort events by date
            sorted_events = sorted(events, key=lambda x: x['datetime'])
            
            # Calculate time differences between consecutive events
            time_diffs = []
            for i in range(1, len(sorted_events)):
                prev_event = sorted_events[i-1]
                curr_event = sorted_events[i]
                
                # Calculate time difference in days
                diff = (curr_event['datetime'] - prev_event['datetime']).total_seconds() / 86400  # Convert to days
                time_diffs.append(diff)
            
            # Calculate mean and standard deviation
            mean_diff = sum(time_diffs) / len(time_diffs)
            std_diff = (sum((x - mean_diff) ** 2 for x in time_diffs) / len(time_diffs)) ** 0.5
            
            # Find anomalies (time differences more than 2 standard deviations from the mean)
            threshold = mean_diff + 2 * std_diff
            
            for i in range(len(time_diffs)):
                if time_diffs[i] > threshold:
                    anomalies.append({
                        'start_date': sorted_events[i]['datetime'].strftime('%Y-%m-%d'),
                        'end_date': sorted_events[i+1]['datetime'].strftime('%Y-%m-%d'),
                        'time_diff_days': time_diffs[i],
                        'threshold_days': threshold,
                        'start_event': sorted_events[i]['title'],
                        'end_event': sorted_events[i+1]['title']
                    })
            
            return anomalies
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Anomaly finding error: {str(e)}")
            return anomalies
    
    def _display_timeline_analysis(self, analysis):
        """Display timeline analysis results."""
        console.print(f"[bold]Timeline Analysis Results:[/]")
        
        # Display basic information
        console.print(f"Total Events: {analysis['event_count']}")
        console.print(f"Date Range: {analysis['date_range'].get('start', 'N/A')} to {analysis['date_range'].get('end', 'N/A')} ({analysis['date_range'].get('duration_days', 'N/A')} days)")
        
        # Display frequency information
        if 'frequency' in analysis:
            console.print(f"Event Frequency: {analysis['frequency'].get('events_per_day', 'N/A'):.2f} events per day, {analysis['frequency'].get('events_per_month', 'N/A'):.2f} events per month")
        
        # Display categories
        if analysis['categories']:
            console.print("[bold]Event Categories:[/]")
            
            # Create table for display
            table = Table(title="Event Categories")
            table.add_column("Category", style="cyan")
            table.add_column("Count", style="green")
            table.add_column("Percentage", style="yellow")
            
            for category, count in analysis['categories'].items():
                percentage = (count / analysis['event_count']) * 100
                table.add_row(category, str(count), f"{percentage:.2f}%")
            
            console.print(table)
        
        # Display gaps
        if analysis['gaps']:
            console.print(f"[bold]Timeline Gaps ({len(analysis['gaps'])}):[/]")
            
            # Create table for display
            table = Table(title="Timeline Gaps")
            table.add_column("Start Date", style="cyan")
            table.add_column("End Date", style="green")
            table.add_column("Duration (days)", style="yellow")
            table.add_column("Start Event", style="magenta")
            table.add_column("End Event", style="blue")
            
            for gap in analysis['gaps']:
                table.add_row(
                    gap['start_date'],
                    gap['end_date'],
                    str(gap['duration_days']),
                    gap['start_event'],
                    gap['end_event']
                )
            
            console.print(table)
        
        # Display clusters
        if analysis['clusters']:
            console.print(f"[bold]Event Clusters ({len(analysis['clusters'])}):[/]")
            
            # Create table for display
            table = Table(title="Event Clusters")
            table.add_column("Start Date", style="cyan")
            table.add_column("End Date", style="green")
            table.add_column("Event Count", style="yellow")
            table.add_column("Events", style="magenta")
            
            for cluster in analysis['clusters']:
                events_str = ", ".join(cluster['events'][:3])
                if len(cluster['events']) > 3:
                    events_str += f"... (+{len(cluster['events']) - 3} more)"
                
                table.add_row(
                    cluster['start_date'],
                    cluster['end_date'],
                    str(cluster['event_count']),
                    events_str
                )
            
            console.print(table)
        
        # Display anomalies
        if analysis['anomalies']:
            console.print(f"[bold]Timeline Anomalies ({len(analysis['anomalies'])}):[/]")
            
            # Create table for display
            table = Table(title="Timeline Anomalies")
            table.add_column("Start Date", style="cyan")
            table.add_column("End Date", style="green")
            table.add_column("Time Diff (days)", style="yellow")
            table.add_column("Threshold (days)", style="magenta")
            table.add_column("Start Event", style="blue")
            table.add_column("End Event", style="purple")
            
            for anomaly in analysis['anomalies']:
                table.add_row(
                    anomaly['start_date'],
                    anomaly['end_date'],
                    f"{anomaly['time_diff_days']:.2f}",
                    f"{anomaly['threshold_days']:.2f}",
                    anomaly['start_event'],
                    anomaly['end_event']
                )
            
            console.print(table)
    
    def _display_timeline_gaps(self, gaps, threshold_hours):
        """Display timeline gaps."""
        if not gaps:
            console.print(f"[bold green]No gaps found in the timeline (threshold: {threshold_hours} hours).[/]")
            return
        
        console.print(f"[bold]Timeline Gaps ({len(gaps)}):[/]")
        
        # Create table for display
        table = Table(title=f"Timeline Gaps (threshold: {threshold_hours} hours)")
        table.add_column("Start Date", style="cyan")
        table.add_column("End Date", style="green")
        table.add_column("Duration (days)", style="yellow")
        table.add_column("Start Event", style="magenta")
        table.add_column("End Event", style="blue")
        
        for gap in gaps:
            table.add_row(
                gap['start_date'],
                gap['end_date'],
                str(gap['duration_days']),
                gap['start_event'],
                gap['end_event']
            )
        
        console.print(table)
    
    def _generate_timeline_analysis_report(self, analysis, output_file):
        """Generate a timeline analysis report."""
        try:
            # Create a plotly figure with subplots
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=("Event Categories", "Event Frequency", "Timeline Gaps", "Event Clusters"),
                specs=[
                    [{"type": "pie"}, {"type": "bar"}],
                    [{"type": "bar"}, {"type": "bar"}]
                ],
                vertical_spacing=0.1,
                horizontal_spacing=0.1
            )
            
            # Add event categories pie chart
            if analysis['categories']:
                categories = list(analysis['categories'].keys())
                counts = list(analysis['categories'].values())
                
                fig.add_trace(
                    go.Pie(
                        labels=categories,
                        values=counts,
                        textinfo='percent+label',
                        marker=dict(colors=[self._get_category_color(cat) for cat in categories])
                    ),
                    row=1, col=1
                )
            
            # Add event frequency bar chart
            if 'frequency' in analysis and analysis['date_range'].get('duration_days', 0) > 0:
                # Create monthly frequency data
                start_date = datetime.strptime(analysis['date_range']['start'], '%Y-%m-%d')
                end_date = datetime.strptime(analysis['date_range']['end'], '%Y-%m-%d')
                
                # Create monthly bins
                months = []
                current_date = start_date
                while current_date <= end_date:
                    months.append(current_date.strftime('%Y-%m'))
                    # Move to next month
                    if current_date.month == 12:
                        current_date = datetime(current_date.year + 1, 1, 1)
                    else:
                        current_date = datetime(current_date.year, current_date.month + 1, 1)
                
                # Count events per month
                month_counts = {month: 0 for month in months}
                
                # Assuming events have 'datetime' attribute from _analyze_timeline_events
                for event in analysis.get('events', []):
                    if 'datetime' in event:
                        month = event['datetime'].strftime('%Y-%m')
                        if month in month_counts:
                            month_counts[month] += 1
                
                fig.add_trace(
                    go.Bar(
                        x=list(month_counts.keys()),
                        y=list(month_counts.values()),
                        marker=dict(color='lightblue'),
                        name='Events per Month'
                    ),
                    row=1, col=2
                )
            
            # Add timeline gaps bar chart
            if analysis['gaps']:
                gap_starts = [gap['start_date'] for gap in analysis['gaps']]
                gap_durations = [gap['duration_days'] for gap in analysis['gaps']]
                
                fig.add_trace(
                    go.Bar(
                        x=gap_starts,
                        y=gap_durations,
                        marker=dict(color='salmon'),
                        name='Gap Duration (days)'
                    ),
                    row=2, col=1
                )
            
            # Add event clusters bar chart
            if analysis['clusters']:
                cluster_starts = [cluster['start_date'] for cluster in analysis['clusters']]
                cluster_counts = [cluster['event_count'] for cluster in analysis['clusters']]
                
                fig.add_trace(
                    go.Bar(
                        x=cluster_starts,
                        y=cluster_counts,
                        marker=dict(color='lightgreen'),
                        name='Events in Cluster'
                    ),
                    row=2, col=2
                )
            
            # Update layout
            fig.update_layout(
                title="Timeline Analysis Report",
                height=800,
                showlegend=False,
                margin=dict(l=50, r=50, t=100, b=50)
            )
            
            # Save the figure
            fig.write_html(output_file)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Analysis report generation error: {str(e)}")
            return False
    
    def _generate_timeline_gaps_report(self, events, gaps, output_file):
        """Generate a timeline gaps report."""
        try:
            # Create a plotly figure
            fig = go.Figure()
            
            # Add events to the timeline
            event_dates = [event['datetime'] for event in events]
            event_categories = [event['category'] for event in events]
            event_titles = [event['title'] for event in events]
            event_descriptions = [event['description'] for event in events]
            event_colors = [event['color'] for event in events]
            
            fig.add_trace(go.Scatter(
                x=event_dates,
                y=event_categories,
                mode='markers',
                marker=dict(
                    size=10,
                    color=event_colors,
                    symbol='circle',
                    line=dict(width=1, color='DarkSlateGrey')
                ),
                text=event_descriptions,
                hoverinfo='text',
                name='Events'
            ))
            
            # Add gaps as shaded regions
            for gap in gaps:
                start_date = datetime.strptime(gap['start_date'], '%Y-%m-%d')
                end_date = datetime.strptime(gap['end_date'], '%Y-%m-%d')
                
                fig.add_vrect(
                    x0=start_date,
                    x1=end_date,
                    fillcolor="red",
                    opacity=0.2,
                    layer="below",
                    line_width=0,
                    annotation_text=f"Gap: {gap['duration_days']} days",
                    annotation_position="top left"
                )
            
            # Update layout
            fig.update_layout(
                title="Timeline Gaps Analysis",
                xaxis=dict(
                    title="Date",
                    showgrid=True,
                    zeroline=False,
                    showline=True,
                    showticklabels=True,
                    type='date'
                ),
                yaxis=dict(
                    title="Category",
                    showgrid=True,
                    zeroline=False,
                    showline=True,
                    showticklabels=True
                ),
                hovermode='closest',
                height=600,
                margin=dict(l=100, r=50, t=100, b=100),
                plot_bgcolor='rgba(240, 240, 240, 0.8)'
            )
            
            # Save the figure
            fig.write_html(output_file)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Gaps report generation error: {str(e)}")
            return False
    
    def _create_merged_timeline_visualization(self, events, output_file):
        """Create a merged timeline visualization."""
        try:
            # Create a plotly figure
            fig = go.Figure()
            
            # Group events by source
            sources = {}
            for event in events:
                source = event.get('source', 'Unknown')
                if source not in sources:
                    sources[source] = []
                sources[source].append(event)
            
            # Add events to the timeline by source
            for source, source_events in sources.items():
                # Extract dates and titles
                dates = [event['datetime'] if 'datetime' in event else self._parse_date(event['date']) for event in source_events]
                titles = [event['title'] for event in source_events]
                descriptions = [event['description'] for event in source_events]
                
                # Add source to the timeline
                fig.add_trace(go.Scatter(
                    x=dates,
                    y=[source] * len(dates),
                    mode='markers',
                    marker=dict(
                        size=15,
                        color=[event['color'] for event in source_events],
                        symbol='circle',
                        line=dict(width=2, color='DarkSlateGrey')
                    ),
                    name=source,
                    text=descriptions,
                    hoverinfo='text'
                ))
            
            # Update layout
            fig.update_layout(
                title="Merged Timeline",
                xaxis=dict(
                    title="Date",
                    showgrid=True,
                    zeroline=False,
                    showline=True,
                    showticklabels=True,
                    type='date'
                ),
                yaxis=dict(
                    title="Source",
                    showgrid=True,
                    zeroline=False,
                    showline=True,
                    showticklabels=True
                ),
                hovermode='closest',
                height=600,
                margin=dict(l=100, r=50, t=100, b=100),
                plot_bgcolor='rgba(240, 240, 240, 0.8)'
            )
            
            # Save the figure
            fig.write_html(output_file)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Merged timeline visualization error: {str(e)}")
            return False
    
    def _create_comparative_timeline_visualization(self, timelines, output_file):
        """Create a comparative timeline visualization."""
        try:
            # Create a plotly figure
            fig = go.Figure()
            
            # Process each timeline
            for timeline in timelines:
                source = timeline['source']
                events = timeline['events']
                
                # Extract dates and titles
                dates = [event['datetime'] if 'datetime' in event else self._parse_date(event['date']) for event in events]
                titles = [event['title'] for event in events]
                descriptions = [event['description'] for event in events]
                
                # Add timeline to the figure
                fig.add_trace(go.Scatter(
                    x=dates,
                    y=[source] * len(dates),
                    mode='markers',
                    marker=dict(
                        size=15,
                        color=[event['color'] for event in events],
                        symbol='circle',
                        line=dict(width=2, color='DarkSlateGrey')
                    ),
                    name=source,
                    text=descriptions,
                    hoverinfo='text'
                ))
            
            # Update layout
            fig.update_layout(
                title="Comparative Timeline",
                xaxis=dict(
                    title="Date",
                    showgrid=True,
                    zeroline=False,
                    showline=True,
                    showticklabels=True,
                    type='date'
                ),
                yaxis=dict(
                    title="Source",
                    showgrid=True,
                    zeroline=False,
                    showline=True,
                    showticklabels=True
                ),
                hovermode='closest',
                height=600,
                margin=dict(l=100, r=50, t=100, b=100),
                plot_bgcolor='rgba(240, 240, 240, 0.8)'
            )
            
            # Save the figure
            fig.write_html(output_file)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Comparative timeline visualization error: {str(e)}")
            return False
