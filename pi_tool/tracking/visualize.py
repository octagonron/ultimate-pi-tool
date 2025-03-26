"""
Connection Visualizer module for the Ultimate PI Tool.

This module provides functionality for visualizing connections and relationships
between entities using various graph and chart types.
"""

import os
import sys
import json
import pandas as pd
import numpy as np
from rich.console import Console
import matplotlib.pyplot as plt
import networkx as nx
import folium
from pyvis.network import Network
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

console = Console()

class ConnectionVisualizer:
    """Connection Visualizer class for creating visual representations of data relationships."""
    
    def __init__(self):
        """Initialize the Connection Visualizer module."""
        pass
    
    def create_graph(self, data_file, output_file=None):
        """Create a network graph visualization from data."""
        console.print(f"[bold blue]Creating network graph from:[/] [bold green]{data_file}[/]")
        
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
                output_file = f"{os.path.splitext(data_file)[0]}_graph.html"
            
            # Create network graph
            graph = self._create_network_graph(data, output_file)
            
            console.print(f"[bold green]Network graph created and saved to:[/] [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def create_map(self, data_file, output_file=None):
        """Create a geographic map visualization from data."""
        console.print(f"[bold blue]Creating geographic map from:[/] [bold green]{data_file}[/]")
        
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
                output_file = f"{os.path.splitext(data_file)[0]}_map.html"
            
            # Create map visualization
            map_vis = self._create_map_visualization(data, output_file)
            
            console.print(f"[bold green]Geographic map created and saved to:[/] [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def create_timeline(self, data_file, output_file=None):
        """Create a timeline visualization from data."""
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
    
    def create_heatmap(self, data_file, output_file=None):
        """Create a heatmap visualization from data."""
        console.print(f"[bold blue]Creating heatmap from:[/] [bold green]{data_file}[/]")
        
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
                output_file = f"{os.path.splitext(data_file)[0]}_heatmap.html"
            
            # Create heatmap visualization
            heatmap = self._create_heatmap_visualization(data, output_file)
            
            console.print(f"[bold green]Heatmap created and saved to:[/] [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def create_sankey(self, data_file, output_file=None):
        """Create a Sankey diagram visualization from data."""
        console.print(f"[bold blue]Creating Sankey diagram from:[/] [bold green]{data_file}[/]")
        
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
                output_file = f"{os.path.splitext(data_file)[0]}_sankey.html"
            
            # Create Sankey diagram
            sankey = self._create_sankey_diagram(data, output_file)
            
            console.print(f"[bold green]Sankey diagram created and saved to:[/] [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def create_dashboard(self, data_files, output_file=None):
        """Create a comprehensive dashboard with multiple visualizations."""
        console.print(f"[bold blue]Creating dashboard from multiple data sources[/]")
        
        try:
            # Check if files exist
            data_list = []
            for data_file in data_files:
                if not os.path.exists(data_file):
                    console.print(f"[bold yellow]Warning:[/] Data file not found: {data_file}")
                    continue
                
                data = self._load_data(data_file)
                
                if data:
                    data_list.append((data_file, data))
                else:
                    console.print(f"[bold yellow]Warning:[/] Failed to load data from: {data_file}")
            
            if not data_list:
                console.print(f"[bold red]Error:[/] Failed to load any data files")
                return False
            
            # Determine output file if not specified
            if not output_file:
                output_file = "investigation_dashboard.html"
            
            # Create dashboard
            dashboard = self._create_dashboard_visualization(data_list, output_file)
            
            console.print(f"[bold green]Dashboard created and saved to:[/] [bold]{output_file}[/]")
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
    
    def _create_network_graph(self, data, output_file):
        """Create an interactive network graph visualization."""
        try:
            # Create a network graph
            net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white")
            
            # Configure physics
            net.barnes_hut(gravity=-80000, central_gravity=0.3, spring_length=250, spring_strength=0.001, damping=0.09)
            
            # Extract nodes and edges from data
            nodes, edges = self._extract_graph_elements(data)
            
            # Add nodes to the graph
            for node_id, node_data in nodes.items():
                net.add_node(
                    node_id, 
                    label=node_data.get('label', node_id),
                    title=node_data.get('title', node_id),
                    color=node_data.get('color', '#6AAFFF'),
                    size=node_data.get('size', 25)
                )
            
            # Add edges to the graph
            for edge in edges:
                source = edge.get('source')
                target = edge.get('target')
                weight = edge.get('weight', 1)
                title = edge.get('title', f"{source} → {target}")
                
                net.add_edge(
                    source, 
                    target, 
                    value=weight,
                    title=title,
                    arrowStrikethrough=False,
                    color={'color': '#FFFFFF', 'opacity': 0.7}
                )
            
            # Set options
            net.set_options("""
            {
              "nodes": {
                "borderWidth": 2,
                "borderWidthSelected": 4,
                "font": {
                  "size": 15,
                  "face": "Tahoma"
                },
                "shadow": true
              },
              "edges": {
                "arrows": {
                  "to": {
                    "enabled": true,
                    "scaleFactor": 0.5
                  }
                },
                "color": {
                  "inherit": false
                },
                "smooth": {
                  "type": "continuous",
                  "forceDirection": "none"
                },
                "shadow": true,
                "width": 2
              },
              "interaction": {
                "hover": true,
                "navigationButtons": true,
                "keyboard": true
              },
              "physics": {
                "stabilization": {
                  "iterations": 100
                }
              }
            }
            """)
            
            # Save the graph
            net.save_graph(output_file)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Network graph creation error: {str(e)}")
            return False
    
    def _extract_graph_elements(self, data):
        """Extract nodes and edges from data for graph visualization."""
        nodes = {}
        edges = []
        
        try:
            # Check if data contains explicit nodes and edges
            if isinstance(data, dict) and 'nodes' in data and 'edges' in data:
                # Direct format with nodes and edges
                for node in data['nodes']:
                    node_id = node.get('id')
                    if node_id:
                        nodes[node_id] = node
                
                edges = data['edges']
            
            elif isinstance(data, dict) and 'entities' in data and 'connections' in data:
                # Format with entities and connections
                for entity in data['entities']:
                    entity_id = entity.get('id')
                    if entity_id:
                        nodes[entity_id] = {
                            'label': entity.get('name', entity_id),
                            'title': entity.get('description', entity_id),
                            'color': entity.get('color', '#6AAFFF'),
                            'size': entity.get('size', 25)
                        }
                
                for connection in data['connections']:
                    source = connection.get('source') or connection.get('from')
                    target = connection.get('target') or connection.get('to')
                    
                    if source and target:
                        edges.append({
                            'source': source,
                            'target': target,
                            'weight': connection.get('weight', 1),
                            'title': connection.get('label', f"{source} → {target}")
                        })
            
            elif isinstance(data, list):
                # List of records - try to infer relationships
                # First, extract all entities as nodes
                for i, record in enumerate(data):
                    if isinstance(record, dict):
                        # Use id field if available, otherwise create a synthetic id
                        entity_id = record.get('id', f"entity_{i}")
                        
                        # Use name or label if available, otherwise use id
                        label = record.get('name', record.get('label', entity_id))
                        
                        # Create node
                        nodes[entity_id] = {
                            'label': label,
                            'title': self._create_tooltip(record),
                            'color': '#6AAFFF',
                            'size': 25
                        }
                
                # Then, look for relationships between records
                for i, record1 in enumerate(data):
                    if isinstance(record1, dict):
                        entity1_id = record1.get('id', f"entity_{i}")
                        
                        for j, record2 in enumerate(data):
                            if i != j and isinstance(record2, dict):
                                entity2_id = record2.get('id', f"entity_{j}")
                                
                                # Look for shared attributes
                                shared_attrs = {}
                                for attr, value1 in record1.items():
                                    if attr in record2 and record2[attr] == value1 and attr not in ['id', 'name', 'label']:
                                        shared_attrs[attr] = value1
                                
                                # If there are shared attributes, create an edge
                                if shared_attrs:
                                    edges.append({
                                        'source': entity1_id,
                                        'target': entity2_id,
                                        'weight': len(shared_attrs),
                                        'title': f"Shared: {', '.join(shared_attrs.keys())}"
                                    })
            
            return nodes, edges
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Graph element extraction error: {str(e)}")
            return {}, []
    
    def _create_tooltip(self, record):
        """Create a tooltip from a record for graph visualization."""
        if not isinstance(record, dict):
            return str(record)
        
        # Create HTML tooltip
        tooltip = "<div style='max-width:300px;'>"
        
        # Add title if available
        if 'name' in record:
            tooltip += f"<h3>{record['name']}</h3>"
        elif 'title' in record:
            tooltip += f"<h3>{record['title']}</h3>"
        
        # Add attributes
        tooltip += "<table style='width:100%;'>"
        for key, value in record.items():
            if key not in ['id', 'name', 'title', 'color', 'size']:
                # Format value based on type
                if isinstance(value, dict):
                    value_str = "Object"
                elif isinstance(value, list):
                    value_str = f"List ({len(value)} items)"
                else:
                    value_str = str(value)
                
                tooltip += f"<tr><td><b>{key}</b></td><td>{value_str}</td></tr>"
        
        tooltip += "</table></div>"
        
        return tooltip
    
    def _create_map_visualization(self, data, output_file):
        """Create a geographic map visualization."""
        try:
            # Extract location data
            locations = self._extract_location_data(data)
            
            if not locations:
                console.print(f"[bold yellow]Warning:[/] No location data found in the dataset")
                return False
            
            # Create a map centered at the average of all coordinates
            avg_lat = sum(loc['lat'] for loc in locations) / len(locations)
            avg_lon = sum(loc['lon'] for loc in locations) / len(locations)
            
            m = folium.Map(location=[avg_lat, avg_lon], zoom_start=5)
            
            # Add markers for each location
            for location in locations:
                popup_content = f"<b>{location['title']}</b><br>{location['description']}"
                
                folium.Marker(
                    [location['lat'], location['lon']],
                    popup=folium.Popup(popup_content, max_width=300),
                    tooltip=location['title'],
                    icon=folium.Icon(color=location['color'], icon=location['icon'])
                ).add_to(m)
            
            # Add connections between related locations
            for connection in locations:
                if 'connections' in connection:
                    for target_id in connection['connections']:
                        # Find target location
                        target = next((loc for loc in locations if loc['id'] == target_id), None)
                        
                        if target:
                            # Draw a line between the locations
                            folium.PolyLine(
                                [[connection['lat'], connection['lon']], [target['lat'], target['lon']]],
                                color='#3388ff',
                                weight=2,
                                opacity=0.7,
                                tooltip=f"{connection['title']} → {target['title']}"
                            ).add_to(m)
            
            # Save the map
            m.save(output_file)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Map visualization error: {str(e)}")
            return False
    
    def _extract_location_data(self, data):
        """Extract location data from the dataset."""
        locations = []
        
        try:
            # Check if data contains explicit location information
            if isinstance(data, dict) and 'locations' in data:
                # Direct format with locations
                return data['locations']
            
            # Try to extract location data from records
            if isinstance(data, list):
                for i, record in enumerate(data):
                    if isinstance(record, dict):
                        # Look for latitude and longitude fields
                        lat = None
                        lon = None
                        
                        # Check various possible field names for coordinates
                        lat_fields = ['lat', 'latitude', 'y', 'LAT', 'LATITUDE']
                        lon_fields = ['lon', 'lng', 'longitude', 'x', 'LON', 'LNG', 'LONGITUDE']
                        
                        for field in lat_fields:
                            if field in record and self._is_numeric(record[field]):
                                lat = float(record[field])
                                break
                        
                        for field in lon_fields:
                            if field in record and self._is_numeric(record[field]):
                                lon = float(record[field])
                                break
                        
                        # If we have coordinates, create a location
                        if lat is not None and lon is not None:
                            # Get title and description
                            title = record.get('name', record.get('title', f"Location {i+1}"))
                            
                            # Create description from record attributes
                            description = ""
                            for key, value in record.items():
                                if key not in ['id', 'name', 'title', 'lat', 'latitude', 'lon', 'lng', 'longitude', 'x', 'y']:
                                    description += f"{key}: {value}<br>"
                            
                            # Create location object
                            location = {
                                'id': record.get('id', f"location_{i}"),
                                'lat': lat,
                                'lon': lon,
                                'title': title,
                                'description': description,
                                'color': 'blue',
                                'icon': 'info-sign'
                            }
                            
                            # Look for connections
                            if 'connections' in record and isinstance(record['connections'], list):
                                location['connections'] = record['connections']
                            
                            locations.append(location)
            
            return locations
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Location data extraction error: {str(e)}")
            return []
    
    def _is_numeric(self, value):
        """Check if a value is numeric."""
        try:
            float(value)
            return True
        except (ValueError, TypeError):
            return False
    
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
            
            # Add events to the timeline
            for event in events:
                fig.add_trace(go.Scatter(
                    x=[event['date']],
                    y=[event['category']],
                    mode='markers',
                    marker=dict(
                        size=15,
                        color=event['color'],
                        symbol=event['symbol'],
                        line=dict(width=2, color='DarkSlateGrey')
                    ),
                    name=event['title'],
                    text=event['description'],
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
    
    def _create_heatmap_visualization(self, data, output_file):
        """Create a heatmap visualization."""
        try:
            # Extract heatmap data
            heatmap_data = self._extract_heatmap_data(data)
            
            if not heatmap_data:
                console.print(f"[bold yellow]Warning:[/] No suitable data found for heatmap visualization")
                return False
            
            # Create a plotly figure
            fig = go.Figure(data=go.Heatmap(
                z=heatmap_data['values'],
                x=heatmap_data['x_labels'],
                y=heatmap_data['y_labels'],
                colorscale='Viridis',
                hoverongaps=False,
                text=heatmap_data['hover_text'] if 'hover_text' in heatmap_data else None,
                hoverinfo='text' if 'hover_text' in heatmap_data else 'z'
            ))
            
            # Update layout
            fig.update_layout(
                title=heatmap_data.get('title', "Data Heatmap"),
                xaxis=dict(title=heatmap_data.get('x_title', "X Axis")),
                yaxis=dict(title=heatmap_data.get('y_title', "Y Axis")),
                height=600,
                margin=dict(l=100, r=50, t=100, b=100)
            )
            
            # Save the figure
            fig.write_html(output_file)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Heatmap visualization error: {str(e)}")
            return False
    
    def _extract_heatmap_data(self, data):
        """Extract data for heatmap visualization."""
        try:
            # Check if data contains explicit heatmap information
            if isinstance(data, dict) and 'heatmap' in data:
                # Direct format with heatmap data
                return data['heatmap']
            
            # Try to create a heatmap from the data
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                # Find numerical fields
                numerical_fields = []
                categorical_fields = []
                
                for key, value in data[0].items():
                    if isinstance(value, (int, float)):
                        numerical_fields.append(key)
                    elif isinstance(value, str):
                        categorical_fields.append(key)
                
                # Need at least one numerical field and two categorical fields
                if len(numerical_fields) > 0 and len(categorical_fields) >= 2:
                    # Use the first numerical field and the first two categorical fields
                    value_field = numerical_fields[0]
                    x_field = categorical_fields[0]
                    y_field = categorical_fields[1]
                    
                    # Extract unique values for x and y axes
                    x_values = sorted(list(set(record[x_field] for record in data if x_field in record)))
                    y_values = sorted(list(set(record[y_field] for record in data if y_field in record)))
                    
                    # Create a matrix for the heatmap
                    matrix = np.zeros((len(y_values), len(x_values)))
                    hover_text = [['' for _ in range(len(x_values))] for _ in range(len(y_values))]
                    
                    # Fill the matrix
                    for record in data:
                        if x_field in record and y_field in record and value_field in record:
                            x_idx = x_values.index(record[x_field])
                            y_idx = y_values.index(record[y_field])
                            matrix[y_idx][x_idx] += record[value_field]
                            hover_text[y_idx][x_idx] = f"{x_field}: {record[x_field]}<br>{y_field}: {record[y_field]}<br>{value_field}: {record[value_field]}"
                    
                    return {
                        'values': matrix,
                        'x_labels': x_values,
                        'y_labels': y_values,
                        'hover_text': hover_text,
                        'title': f"{value_field} by {x_field} and {y_field}",
                        'x_title': x_field,
                        'y_title': y_field
                    }
            
            # If we couldn't create a heatmap, return None
            return None
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Heatmap data extraction error: {str(e)}")
            return None
    
    def _create_sankey_diagram(self, data, output_file):
        """Create a Sankey diagram visualization."""
        try:
            # Extract Sankey data
            sankey_data = self._extract_sankey_data(data)
            
            if not sankey_data:
                console.print(f"[bold yellow]Warning:[/] No suitable data found for Sankey diagram")
                return False
            
            # Create a plotly figure
            fig = go.Figure(data=[go.Sankey(
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5),
                    label=sankey_data['node_labels'],
                    color=sankey_data.get('node_colors', "blue")
                ),
                link=dict(
                    source=sankey_data['source'],
                    target=sankey_data['target'],
                    value=sankey_data['value'],
                    label=sankey_data.get('link_labels', None),
                    color=sankey_data.get('link_colors', "rgba(100, 100, 100, 0.2)")
                )
            )])
            
            # Update layout
            fig.update_layout(
                title=sankey_data.get('title', "Sankey Diagram"),
                font=dict(size=12),
                height=600,
                margin=dict(l=50, r=50, t=100, b=50)
            )
            
            # Save the figure
            fig.write_html(output_file)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Sankey diagram error: {str(e)}")
            return False
    
    def _extract_sankey_data(self, data):
        """Extract data for Sankey diagram visualization."""
        try:
            # Check if data contains explicit Sankey information
            if isinstance(data, dict) and 'sankey' in data:
                # Direct format with Sankey data
                return data['sankey']
            
            # Try to create a Sankey diagram from the data
            if isinstance(data, list):
                # Look for flow data (source, target, value)
                sources = []
                targets = []
                values = []
                
                # Check if data contains explicit flow information
                flow_found = False
                
                for record in data:
                    if isinstance(record, dict):
                        # Look for source, target, value fields
                        source = None
                        target = None
                        value = None
                        
                        # Check various possible field names
                        source_fields = ['source', 'from', 'origin', 'src']
                        target_fields = ['target', 'to', 'destination', 'dst']
                        value_fields = ['value', 'amount', 'weight', 'count']
                        
                        for field in source_fields:
                            if field in record:
                                source = record[field]
                                break
                        
                        for field in target_fields:
                            if field in record:
                                target = record[field]
                                break
                        
                        for field in value_fields:
                            if field in record and self._is_numeric(record[field]):
                                value = float(record[field])
                                break
                        
                        # If we have all three, add to the flow data
                        if source is not None and target is not None and value is not None:
                            sources.append(source)
                            targets.append(target)
                            values.append(value)
                            flow_found = True
                
                if flow_found:
                    # Create node labels (unique sources and targets)
                    all_nodes = list(set(sources + targets))
                    
                    # Map node names to indices
                    node_indices = {node: i for i, node in enumerate(all_nodes)}
                    
                    # Convert sources and targets to indices
                    source_indices = [node_indices[source] for source in sources]
                    target_indices = [node_indices[target] for target in targets]
                    
                    return {
                        'node_labels': all_nodes,
                        'source': source_indices,
                        'target': target_indices,
                        'value': values,
                        'title': "Flow Diagram"
                    }
            
            # If we couldn't create a Sankey diagram, return None
            return None
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Sankey data extraction error: {str(e)}")
            return None
    
    def _create_dashboard_visualization(self, data_list, output_file):
        """Create a comprehensive dashboard with multiple visualizations."""
        try:
            # Create a plotly figure with subplots
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=("Network Graph", "Timeline", "Heatmap", "Statistics"),
                specs=[
                    [{"type": "scatter"}, {"type": "scatter"}],
                    [{"type": "heatmap"}, {"type": "bar"}]
                ],
                vertical_spacing=0.1,
                horizontal_spacing=0.1
            )
            
            # Process each data source
            all_nodes = set()
            all_edges = []
            all_events = []
            
            for data_file, data in data_list:
                # Extract graph elements
                nodes, edges = self._extract_graph_elements(data)
                all_nodes.update(nodes.keys())
                all_edges.extend(edges)
                
                # Extract timeline events
                events = self._extract_timeline_events(data)
                all_events.extend(events)
                
                # Extract heatmap data
                heatmap_data = self._extract_heatmap_data(data)
                if heatmap_data:
                    # Add heatmap to the dashboard
                    fig.add_trace(
                        go.Heatmap(
                            z=heatmap_data['values'],
                            x=heatmap_data['x_labels'],
                            y=heatmap_data['y_labels'],
                            colorscale='Viridis',
                            hoverongaps=False
                        ),
                        row=2, col=1
                    )
            
            # Create a simplified network graph for the dashboard
            if all_nodes and all_edges:
                # Create a networkx graph
                G = nx.Graph()
                
                # Add nodes
                for node in all_nodes:
                    G.add_node(node)
                
                # Add edges
                for edge in all_edges:
                    source = edge.get('source')
                    target = edge.get('target')
                    weight = edge.get('weight', 1)
                    
                    if source in all_nodes and target in all_nodes:
                        G.add_edge(source, target, weight=weight)
                
                # Get node positions
                pos = nx.spring_layout(G)
                
                # Add nodes to the plot
                node_x = []
                node_y = []
                for node in G.nodes():
                    x, y = pos[node]
                    node_x.append(x)
                    node_y.append(y)
                
                fig.add_trace(
                    go.Scatter(
                        x=node_x, y=node_y,
                        mode='markers',
                        marker=dict(
                            size=10,
                            color='blue',
                            line=dict(width=1, color='black')
                        ),
                        text=list(G.nodes()),
                        hoverinfo='text',
                        name='Nodes'
                    ),
                    row=1, col=1
                )
                
                # Add edges to the plot
                edge_x = []
                edge_y = []
                for edge in G.edges():
                    x0, y0 = pos[edge[0]]
                    x1, y1 = pos[edge[1]]
                    edge_x.extend([x0, x1, None])
                    edge_y.extend([y0, y1, None])
                
                fig.add_trace(
                    go.Scatter(
                        x=edge_x, y=edge_y,
                        mode='lines',
                        line=dict(width=0.5, color='gray'),
                        hoverinfo='none',
                        name='Connections'
                    ),
                    row=1, col=1
                )
            
            # Add timeline to the dashboard
            if all_events:
                # Sort events by date
                all_events.sort(key=lambda x: x['date'])
                
                # Extract dates and categories
                dates = [event['date'] for event in all_events]
                categories = [event['category'] for event in all_events]
                
                # Add events to the timeline
                fig.add_trace(
                    go.Scatter(
                        x=dates,
                        y=categories,
                        mode='markers',
                        marker=dict(
                            size=10,
                            color=[self._get_category_color(cat) for cat in categories],
                            symbol='circle',
                            line=dict(width=1, color='DarkSlateGrey')
                        ),
                        text=[event['description'] for event in all_events],
                        hoverinfo='text',
                        name='Events'
                    ),
                    row=1, col=2
                )
            
            # Add statistics to the dashboard
            # Count entities by type
            entity_types = {}
            for data_file, data in data_list:
                if isinstance(data, list):
                    for record in data:
                        if isinstance(record, dict) and 'type' in record:
                            entity_type = record['type']
                            entity_types[entity_type] = entity_types.get(entity_type, 0) + 1
            
            if entity_types:
                # Add bar chart of entity types
                fig.add_trace(
                    go.Bar(
                        x=list(entity_types.keys()),
                        y=list(entity_types.values()),
                        marker=dict(color='lightblue'),
                        name='Entity Types'
                    ),
                    row=2, col=2
                )
            
            # Update layout
            fig.update_layout(
                title="Investigation Dashboard",
                height=800,
                showlegend=False,
                margin=dict(l=50, r=50, t=100, b=50)
            )
            
            # Update axes
            fig.update_xaxes(title_text="", row=1, col=1)
            fig.update_yaxes(title_text="", row=1, col=1)
            
            fig.update_xaxes(title_text="Date", row=1, col=2)
            fig.update_yaxes(title_text="Category", row=1, col=2)
            
            fig.update_xaxes(title_text="", row=2, col=1)
            fig.update_yaxes(title_text="", row=2, col=1)
            
            fig.update_xaxes(title_text="Entity Type", row=2, col=2)
            fig.update_yaxes(title_text="Count", row=2, col=2)
            
            # Save the dashboard
            fig.write_html(output_file)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Dashboard creation error: {str(e)}")
            return False
