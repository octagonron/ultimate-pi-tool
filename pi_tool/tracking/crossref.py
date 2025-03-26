"""
Cross-Referencer module for the Ultimate PI Tool.

This module provides functionality for cross-referencing data from various sources
to identify connections and patterns.
"""

import os
import sys
import json
import pandas as pd
import numpy as np
from rich.console import Console
from rich.table import Table
import networkx as nx
import matplotlib.pyplot as plt

console = Console()

class CrossReferencer:
    """Cross-Referencer class for analyzing and comparing data from multiple sources."""
    
    def __init__(self):
        """Initialize the Cross-Referencer module."""
        pass
    
    def analyze_data(self, data_file):
        """Analyze data from a file to identify patterns and connections."""
        console.print(f"[bold blue]Analyzing data from:[/] [bold green]{data_file}[/]")
        
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
            
            # Analyze data
            results = self._analyze_data_structure(data)
            
            # Display results
            self._display_analysis_results(results)
            
            # Identify connections
            connections = self._identify_connections(data)
            
            # Display connections
            self._display_connections(connections)
            
            # Generate graph visualization
            graph_file = f"{os.path.splitext(data_file)[0]}_graph.png"
            self._generate_graph_visualization(connections, graph_file)
            
            console.print(f"[bold green]Analysis complete. Graph visualization saved to:[/] [bold]{graph_file}[/]")
            
            return {
                'results': results,
                'connections': connections,
                'graph_file': graph_file
            }
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def compare_data(self, data_file1, data_file2):
        """Compare data from two files to identify similarities and differences."""
        console.print(f"[bold blue]Comparing data from:[/] [bold green]{data_file1}[/] and [bold green]{data_file2}[/]")
        
        try:
            # Check if files exist
            if not os.path.exists(data_file1):
                console.print(f"[bold red]Error:[/] Data file not found: {data_file1}")
                return False
            
            if not os.path.exists(data_file2):
                console.print(f"[bold red]Error:[/] Data file not found: {data_file2}")
                return False
            
            # Load data
            data1 = self._load_data(data_file1)
            data2 = self._load_data(data_file2)
            
            if not data1 or not data2:
                console.print(f"[bold red]Error:[/] Failed to load data from one or both files")
                return False
            
            # Compare data
            comparison = self._compare_data_structures(data1, data2)
            
            # Display comparison results
            self._display_comparison_results(comparison)
            
            # Generate comparison visualization
            comparison_file = f"comparison_{os.path.basename(data_file1)}_{os.path.basename(data_file2)}.png"
            self._generate_comparison_visualization(comparison, comparison_file)
            
            console.print(f"[bold green]Comparison complete. Visualization saved to:[/] [bold]{comparison_file}[/]")
            
            return {
                'comparison': comparison,
                'visualization_file': comparison_file
            }
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def cross_reference_entities(self, entities_file, sources_list):
        """Cross-reference entities across multiple data sources."""
        console.print(f"[bold blue]Cross-referencing entities from:[/] [bold green]{entities_file}[/]")
        
        try:
            # Check if files exist
            if not os.path.exists(entities_file):
                console.print(f"[bold red]Error:[/] Entities file not found: {entities_file}")
                return False
            
            # Load entities
            entities = self._load_data(entities_file)
            
            if not entities:
                console.print(f"[bold red]Error:[/] Failed to load entities from: {entities_file}")
                return False
            
            # Load sources
            sources_data = {}
            for source_file in sources_list:
                if not os.path.exists(source_file):
                    console.print(f"[bold yellow]Warning:[/] Source file not found: {source_file}")
                    continue
                
                source_data = self._load_data(source_file)
                
                if source_data:
                    sources_data[source_file] = source_data
                else:
                    console.print(f"[bold yellow]Warning:[/] Failed to load data from: {source_file}")
            
            if not sources_data:
                console.print(f"[bold red]Error:[/] Failed to load any source data")
                return False
            
            # Cross-reference entities with sources
            cross_ref = self._cross_reference_data(entities, sources_data)
            
            # Display cross-reference results
            self._display_cross_reference_results(cross_ref)
            
            # Generate cross-reference visualization
            cross_ref_file = f"cross_ref_{os.path.basename(entities_file)}.png"
            self._generate_cross_reference_visualization(cross_ref, cross_ref_file)
            
            console.print(f"[bold green]Cross-reference complete. Visualization saved to:[/] [bold]{cross_ref_file}[/]")
            
            return {
                'cross_ref': cross_ref,
                'visualization_file': cross_ref_file
            }
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def find_common_patterns(self, data_files):
        """Find common patterns across multiple data files."""
        console.print(f"[bold blue]Finding common patterns across {len(data_files)} data files[/]")
        
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
            
            if len(data_list) < 2:
                console.print(f"[bold red]Error:[/] Need at least 2 valid data files to find common patterns")
                return False
            
            # Find common patterns
            patterns = self._find_common_patterns(data_list)
            
            # Display patterns
            self._display_common_patterns(patterns)
            
            # Generate patterns visualization
            patterns_file = f"common_patterns_{len(data_files)}_files.png"
            self._generate_patterns_visualization(patterns, patterns_file)
            
            console.print(f"[bold green]Pattern analysis complete. Visualization saved to:[/] [bold]{patterns_file}[/]")
            
            return {
                'patterns': patterns,
                'visualization_file': patterns_file
            }
            
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
    
    def _analyze_data_structure(self, data):
        """Analyze the structure of data to identify key fields and patterns."""
        results = {
            'entity_count': 0,
            'fields': {},
            'unique_values': {},
            'common_values': {},
            'patterns': []
        }
        
        try:
            # Handle different data structures
            if isinstance(data, list):
                # List of records
                results['entity_count'] = len(data)
                
                # Analyze fields
                if results['entity_count'] > 0 and isinstance(data[0], dict):
                    # Get all fields
                    all_fields = set()
                    for record in data:
                        all_fields.update(record.keys())
                    
                    # Analyze each field
                    for field in all_fields:
                        # Count occurrences
                        field_count = sum(1 for record in data if field in record)
                        
                        # Calculate percentage
                        field_percentage = (field_count / results['entity_count']) * 100
                        
                        # Add to fields
                        results['fields'][field] = {
                            'count': field_count,
                            'percentage': field_percentage,
                            'sample': next((record[field] for record in data if field in record), None)
                        }
                        
                        # Analyze values
                        values = [record[field] for record in data if field in record]
                        unique_values = set(str(v) for v in values if v is not None)
                        
                        # Add to unique values
                        results['unique_values'][field] = len(unique_values)
                        
                        # Find common values
                        if len(unique_values) < len(values) / 2:  # Only if there are repeated values
                            value_counts = {}
                            for value in values:
                                if value is not None:
                                    value_str = str(value)
                                    value_counts[value_str] = value_counts.get(value_str, 0) + 1
                            
                            # Get top 5 common values
                            common_values = sorted(value_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                            
                            # Add to common values
                            results['common_values'][field] = [
                                {'value': value, 'count': count}
                                for value, count in common_values
                            ]
                
                # Identify patterns
                results['patterns'] = self._identify_data_patterns(data)
                
            elif isinstance(data, dict):
                # Single record or nested structure
                results['entity_count'] = 1
                
                # Analyze fields
                for field, value in data.items():
                    results['fields'][field] = {
                        'count': 1,
                        'percentage': 100.0,
                        'sample': value
                    }
                    
                    # If value is a list, analyze it recursively
                    if isinstance(value, list) and len(value) > 0:
                        sub_results = self._analyze_data_structure(value)
                        results['patterns'].append({
                            'field': field,
                            'type': 'list',
                            'count': len(value),
                            'sub_analysis': sub_results
                        })
                    
                    # If value is a dict, analyze it recursively
                    elif isinstance(value, dict):
                        sub_results = self._analyze_data_structure(value)
                        results['patterns'].append({
                            'field': field,
                            'type': 'dict',
                            'sub_analysis': sub_results
                        })
            
            return results
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Data analysis error: {str(e)}")
            return results
    
    def _identify_data_patterns(self, data):
        """Identify patterns in the data."""
        patterns = []
        
        try:
            if not isinstance(data, list) or len(data) == 0:
                return patterns
            
            # Check for date patterns
            date_fields = []
            for record in data:
                if isinstance(record, dict):
                    for field, value in record.items():
                        if isinstance(value, str):
                            # Check for date-like patterns
                            if any(date_pattern in value for date_pattern in ['-', '/', '.']):
                                date_fields.append(field)
            
            # Count occurrences of each date field
            date_field_counts = {}
            for field in date_fields:
                date_field_counts[field] = date_field_counts.get(field, 0) + 1
            
            # Add date patterns
            for field, count in date_field_counts.items():
                if count > len(data) / 2:  # Only if it appears in more than half the records
                    patterns.append({
                        'type': 'date_field',
                        'field': field,
                        'count': count
                    })
            
            # Check for numerical patterns
            num_fields = []
            for record in data:
                if isinstance(record, dict):
                    for field, value in record.items():
                        if isinstance(value, (int, float)):
                            num_fields.append(field)
            
            # Count occurrences of each numerical field
            num_field_counts = {}
            for field in num_fields:
                num_field_counts[field] = num_field_counts.get(field, 0) + 1
            
            # Add numerical patterns
            for field, count in num_field_counts.items():
                if count > len(data) / 2:  # Only if it appears in more than half the records
                    patterns.append({
                        'type': 'numerical_field',
                        'field': field,
                        'count': count
                    })
            
            # Check for nested structures
            nested_fields = []
            for record in data:
                if isinstance(record, dict):
                    for field, value in record.items():
                        if isinstance(value, (list, dict)):
                            nested_fields.append((field, type(value).__name__))
            
            # Count occurrences of each nested field
            nested_field_counts = {}
            for field, type_name in nested_fields:
                key = f"{field}:{type_name}"
                nested_field_counts[key] = nested_field_counts.get(key, 0) + 1
            
            # Add nested structure patterns
            for key, count in nested_field_counts.items():
                field, type_name = key.split(':')
                if count > len(data) / 2:  # Only if it appears in more than half the records
                    patterns.append({
                        'type': 'nested_structure',
                        'field': field,
                        'structure_type': type_name,
                        'count': count
                    })
            
            return patterns
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Pattern identification error: {str(e)}")
            return patterns
    
    def _identify_connections(self, data):
        """Identify connections between entities in the data."""
        connections = []
        
        try:
            if not isinstance(data, list) or len(data) == 0:
                return connections
            
            # Extract entities and their attributes
            entities = {}
            for i, record in enumerate(data):
                if isinstance(record, dict):
                    entity_id = record.get('id', f"entity_{i}")
                    entities[entity_id] = record
            
            # Find connections based on shared attributes
            for entity1_id, entity1 in entities.items():
                for entity2_id, entity2 in entities.items():
                    if entity1_id != entity2_id:
                        # Find shared attributes
                        shared_attrs = {}
                        for attr, value1 in entity1.items():
                            if attr in entity2 and entity2[attr] == value1:
                                shared_attrs[attr] = value1
                        
                        if shared_attrs:
                            connections.append({
                                'entity1': entity1_id,
                                'entity2': entity2_id,
                                'shared_attributes': shared_attrs,
                                'strength': len(shared_attrs)
                            })
            
            return connections
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Connection identification error: {str(e)}")
            return connections
    
    def _compare_data_structures(self, data1, data2):
        """Compare two data structures to identify similarities and differences."""
        comparison = {
            'common_fields': [],
            'unique_fields_data1': [],
            'unique_fields_data2': [],
            'common_values': [],
            'different_values': [],
            'structure_similarity': 0.0
        }
        
        try:
            # Extract fields from both data structures
            fields1 = self._extract_fields(data1)
            fields2 = self._extract_fields(data2)
            
            # Find common and unique fields
            common_fields = fields1.intersection(fields2)
            unique_fields1 = fields1 - fields2
            unique_fields2 = fields2 - fields1
            
            comparison['common_fields'] = list(common_fields)
            comparison['unique_fields_data1'] = list(unique_fields1)
            comparison['unique_fields_data2'] = list(unique_fields2)
            
            # Calculate structure similarity
            total_fields = len(fields1.union(fields2))
            if total_fields > 0:
                comparison['structure_similarity'] = (len(common_fields) / total_fields) * 100
            
            # Compare values for common fields
            if isinstance(data1, list) and isinstance(data2, list):
                for field in common_fields:
                    values1 = [record.get(field) for record in data1 if isinstance(record, dict) and field in record]
                    values2 = [record.get(field) for record in data2 if isinstance(record, dict) and field in record]
                    
                    # Find common values
                    common_values = set(str(v) for v in values1 if v is not None).intersection(
                        set(str(v) for v in values2 if v is not None)
                    )
                    
                    if common_values:
                        comparison['common_values'].append({
                            'field': field,
                            'values': list(common_values)[:5]  # Limit to 5 examples
                        })
                    
                    # Find different values
                    values1_set = set(str(v) for v in values1 if v is not None)
                    values2_set = set(str(v) for v in values2 if v is not None)
                    
                    diff_values1 = values1_set - values2_set
                    diff_values2 = values2_set - values1_set
                    
                    if diff_values1 or diff_values2:
                        comparison['different_values'].append({
                            'field': field,
                            'values_data1': list(diff_values1)[:5],  # Limit to 5 examples
                            'values_data2': list(diff_values2)[:5]   # Limit to 5 examples
                        })
            
            return comparison
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Data comparison error: {str(e)}")
            return comparison
    
    def _extract_fields(self, data):
        """Extract all fields from a data structure."""
        fields = set()
        
        try:
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        fields.update(item.keys())
            elif isinstance(data, dict):
                fields.update(data.keys())
            
            return fields
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Field extraction error: {str(e)}")
            return fields
    
    def _cross_reference_data(self, entities, sources_data):
        """Cross-reference entities with multiple data sources."""
        cross_ref = {
            'entities': [],
            'sources': [],
            'matches': []
        }
        
        try:
            # Extract entity identifiers
            entity_ids = []
            if isinstance(entities, list):
                for i, entity in enumerate(entities):
                    if isinstance(entity, dict):
                        entity_id = entity.get('id', f"entity_{i}")
                        entity_ids.append((entity_id, entity))
            elif isinstance(entities, dict):
                for entity_id, entity in entities.items():
                    entity_ids.append((entity_id, entity))
            
            cross_ref['entities'] = [{'id': entity_id, 'data': entity} for entity_id, entity in entity_ids]
            
            # Process each source
            for source_file, source_data in sources_data.items():
                source_id = os.path.basename(source_file)
                cross_ref['sources'].append({'id': source_id, 'file': source_file})
                
                # Find matches for each entity
                for entity_id, entity in entity_ids:
                    matches = self._find_entity_matches(entity, source_data)
                    
                    if matches:
                        for match in matches:
                            cross_ref['matches'].append({
                                'entity_id': entity_id,
                                'source_id': source_id,
                                'match_data': match['data'],
                                'match_score': match['score'],
                                'shared_attributes': match['shared_attributes']
                            })
            
            return cross_ref
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Cross-reference error: {str(e)}")
            return cross_ref
    
    def _find_entity_matches(self, entity, source_data):
        """Find matches for an entity in source data."""
        matches = []
        
        try:
            if not isinstance(entity, dict):
                return matches
            
            # Process source data
            if isinstance(source_data, list):
                for item in source_data:
                    if isinstance(item, dict):
                        # Find shared attributes
                        shared_attrs = {}
                        for attr, value in entity.items():
                            if attr in item and item[attr] == value:
                                shared_attrs[attr] = value
                        
                        # Calculate match score
                        score = 0
                        if shared_attrs:
                            # Simple scoring: percentage of entity attributes that match
                            score = (len(shared_attrs) / len(entity)) * 100
                        
                        # Add match if score is above threshold
                        if score >= 30:  # Arbitrary threshold
                            matches.append({
                                'data': item,
                                'score': score,
                                'shared_attributes': shared_attrs
                            })
            
            # Sort matches by score
            matches.sort(key=lambda x: x['score'], reverse=True)
            
            return matches
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Entity matching error: {str(e)}")
            return matches
    
    def _find_common_patterns(self, data_list):
        """Find common patterns across multiple data sources."""
        patterns = {
            'common_fields': [],
            'common_values': [],
            'structural_patterns': []
        }
        
        try:
            # Extract fields from each data source
            all_fields = []
            for _, data in data_list:
                fields = self._extract_fields(data)
                all_fields.append(fields)
            
            # Find fields common to all data sources
            if all_fields:
                common_fields = set.intersection(*all_fields)
                patterns['common_fields'] = list(common_fields)
            
            # Find common values for common fields
            for field in patterns['common_fields']:
                field_values = []
                for _, data in data_list:
                    values = self._extract_field_values(data, field)
                    field_values.append(values)
                
                # Find values common to all data sources
                if field_values:
                    common_values = set.intersection(*field_values)
                    if common_values:
                        patterns['common_values'].append({
                            'field': field,
                            'values': list(common_values)[:5]  # Limit to 5 examples
                        })
            
            # Analyze structural patterns
            structure_analyses = []
            for file_name, data in data_list:
                analysis = self._analyze_data_structure(data)
                structure_analyses.append((file_name, analysis))
            
            # Find common structural patterns
            common_patterns = self._find_common_structural_patterns(structure_analyses)
            patterns['structural_patterns'] = common_patterns
            
            return patterns
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Pattern finding error: {str(e)}")
            return patterns
    
    def _extract_field_values(self, data, field):
        """Extract all values for a specific field from data."""
        values = set()
        
        try:
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and field in item:
                        value = item[field]
                        if value is not None:
                            values.add(str(value))
            elif isinstance(data, dict) and field in data:
                value = data[field]
                if value is not None:
                    values.add(str(value))
            
            return values
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Value extraction error: {str(e)}")
            return values
    
    def _find_common_structural_patterns(self, structure_analyses):
        """Find structural patterns common to multiple data analyses."""
        common_patterns = []
        
        try:
            if not structure_analyses:
                return common_patterns
            
            # Extract patterns from each analysis
            all_patterns = []
            for _, analysis in structure_analyses:
                patterns = analysis.get('patterns', [])
                all_patterns.append(patterns)
            
            # Group patterns by type and field
            pattern_groups = {}
            for i, patterns in enumerate(all_patterns):
                for pattern in patterns:
                    pattern_type = pattern.get('type', '')
                    pattern_field = pattern.get('field', '')
                    key = f"{pattern_type}:{pattern_field}"
                    
                    if key not in pattern_groups:
                        pattern_groups[key] = []
                    
                    pattern_groups[key].append((i, pattern))
            
            # Find patterns that appear in all analyses
            for key, patterns in pattern_groups.items():
                if len(patterns) == len(structure_analyses):
                    pattern_type, pattern_field = key.split(':')
                    common_patterns.append({
                        'type': pattern_type,
                        'field': pattern_field,
                        'occurrences': len(patterns)
                    })
            
            return common_patterns
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Structural pattern finding error: {str(e)}")
            return common_patterns
    
    def _display_analysis_results(self, results):
        """Display data analysis results."""
        console.print(f"[bold]Data Analysis Results:[/]")
        console.print(f"Entity Count: {results['entity_count']}")
        
        # Display fields
        if results['fields']:
            table = Table(title="Fields Analysis")
            table.add_column("Field", style="cyan")
            table.add_column("Count", style="green")
            table.add_column("Percentage", style="yellow")
            table.add_column("Sample", style="magenta")
            
            for field, info in results['fields'].items():
                table.add_row(
                    field,
                    str(info['count']),
                    f"{info['percentage']:.2f}%",
                    str(info['sample'])[:50]  # Limit sample length
                )
            
            console.print(table)
        
        # Display patterns
        if results['patterns']:
            console.print("[bold]Identified Patterns:[/]")
            for pattern in results['patterns']:
                pattern_type = pattern.get('type', '')
                pattern_field = pattern.get('field', '')
                
                if pattern_type == 'date_field':
                    console.print(f"- Field '{pattern_field}' appears to contain dates")
                elif pattern_type == 'numerical_field':
                    console.print(f"- Field '{pattern_field}' contains numerical values")
                elif pattern_type == 'nested_structure':
                    structure_type = pattern.get('structure_type', '')
                    console.print(f"- Field '{pattern_field}' contains nested {structure_type} structure")
    
    def _display_connections(self, connections):
        """Display identified connections."""
        if not connections:
            console.print("[bold yellow]No connections identified.[/]")
            return
        
        console.print(f"[bold]Identified Connections ({len(connections)}):[/]")
        
        # Create table for display
        table = Table(title="Entity Connections")
        table.add_column("Entity 1", style="cyan")
        table.add_column("Entity 2", style="green")
        table.add_column("Shared Attributes", style="yellow")
        table.add_column("Strength", style="magenta")
        
        # Sort connections by strength
        sorted_connections = sorted(connections, key=lambda x: x.get('strength', 0), reverse=True)
        
        # Display top 10 connections
        for connection in sorted_connections[:10]:
            entity1 = connection.get('entity1', '')
            entity2 = connection.get('entity2', '')
            shared_attrs = connection.get('shared_attributes', {})
            strength = connection.get('strength', 0)
            
            # Format shared attributes
            attrs_str = ', '.join(f"{k}={v}" for k, v in shared_attrs.items())
            
            table.add_row(
                entity1,
                entity2,
                attrs_str,
                str(strength)
            )
        
        console.print(table)
        
        if len(connections) > 10:
            console.print(f"[bold]... and {len(connections) - 10} more connections[/]")
    
    def _display_comparison_results(self, comparison):
        """Display data comparison results."""
        console.print(f"[bold]Data Comparison Results:[/]")
        console.print(f"Structure Similarity: {comparison['structure_similarity']:.2f}%")
        
        # Display common fields
        if comparison['common_fields']:
            console.print(f"[bold]Common Fields ({len(comparison['common_fields'])}):[/]")
            for field in comparison['common_fields']:
                console.print(f"- {field}")
        
        # Display unique fields
        if comparison['unique_fields_data1']:
            console.print(f"[bold]Fields Unique to Data 1 ({len(comparison['unique_fields_data1'])}):[/]")
            for field in comparison['unique_fields_data1']:
                console.print(f"- {field}")
        
        if comparison['unique_fields_data2']:
            console.print(f"[bold]Fields Unique to Data 2 ({len(comparison['unique_fields_data2'])}):[/]")
            for field in comparison['unique_fields_data2']:
                console.print(f"- {field}")
        
        # Display common values
        if comparison['common_values']:
            console.print(f"[bold]Fields with Common Values ({len(comparison['common_values'])}):[/]")
            for item in comparison['common_values']:
                field = item.get('field', '')
                values = item.get('values', [])
                values_str = ', '.join(values)
                console.print(f"- {field}: {values_str}")
        
        # Display different values
        if comparison['different_values']:
            console.print(f"[bold]Fields with Different Values ({len(comparison['different_values'])}):[/]")
            for item in comparison['different_values']:
                field = item.get('field', '')
                values1 = item.get('values_data1', [])
                values2 = item.get('values_data2', [])
                console.print(f"- {field}:")
                console.print(f"  Data 1: {', '.join(values1)}")
                console.print(f"  Data 2: {', '.join(values2)}")
    
    def _display_cross_reference_results(self, cross_ref):
        """Display cross-reference results."""
        entities = cross_ref.get('entities', [])
        sources = cross_ref.get('sources', [])
        matches = cross_ref.get('matches', [])
        
        console.print(f"[bold]Cross-Reference Results:[/]")
        console.print(f"Entities: {len(entities)}")
        console.print(f"Sources: {len(sources)}")
        console.print(f"Total Matches: {len(matches)}")
        
        # Group matches by entity
        entity_matches = {}
        for match in matches:
            entity_id = match.get('entity_id', '')
            if entity_id not in entity_matches:
                entity_matches[entity_id] = []
            entity_matches[entity_id].append(match)
        
        # Display matches for each entity
        for entity_id, entity_matches_list in entity_matches.items():
            console.print(f"[bold]Entity: {entity_id}[/]")
            
            # Create table for display
            table = Table(title=f"Matches for {entity_id}")
            table.add_column("Source", style="cyan")
            table.add_column("Match Score", style="green")
            table.add_column("Shared Attributes", style="yellow")
            
            # Sort matches by score
            sorted_matches = sorted(entity_matches_list, key=lambda x: x.get('match_score', 0), reverse=True)
            
            for match in sorted_matches:
                source_id = match.get('source_id', '')
                match_score = match.get('match_score', 0)
                shared_attrs = match.get('shared_attributes', {})
                
                # Format shared attributes
                attrs_str = ', '.join(f"{k}={v}" for k, v in shared_attrs.items())
                
                table.add_row(
                    source_id,
                    f"{match_score:.2f}%",
                    attrs_str
                )
            
            console.print(table)
    
    def _display_common_patterns(self, patterns):
        """Display common patterns."""
        common_fields = patterns.get('common_fields', [])
        common_values = patterns.get('common_values', [])
        structural_patterns = patterns.get('structural_patterns', [])
        
        console.print(f"[bold]Common Patterns Analysis:[/]")
        
        # Display common fields
        if common_fields:
            console.print(f"[bold]Fields Common to All Sources ({len(common_fields)}):[/]")
            for field in common_fields:
                console.print(f"- {field}")
        
        # Display common values
        if common_values:
            console.print(f"[bold]Common Values Across All Sources ({len(common_values)}):[/]")
            for item in common_values:
                field = item.get('field', '')
                values = item.get('values', [])
                values_str = ', '.join(values)
                console.print(f"- {field}: {values_str}")
        
        # Display structural patterns
        if structural_patterns:
            console.print(f"[bold]Common Structural Patterns ({len(structural_patterns)}):[/]")
            for pattern in structural_patterns:
                pattern_type = pattern.get('type', '')
                pattern_field = pattern.get('field', '')
                occurrences = pattern.get('occurrences', 0)
                
                console.print(f"- {pattern_type} pattern in field '{pattern_field}' (found in {occurrences} sources)")
    
    def _generate_graph_visualization(self, connections, output_file):
        """Generate a graph visualization of connections."""
        try:
            # Create graph
            G = nx.Graph()
            
            # Add nodes and edges
            for connection in connections:
                entity1 = connection.get('entity1', '')
                entity2 = connection.get('entity2', '')
                strength = connection.get('strength', 1)
                
                # Add nodes if they don't exist
                if not G.has_node(entity1):
                    G.add_node(entity1)
                
                if not G.has_node(entity2):
                    G.add_node(entity2)
                
                # Add edge with weight based on strength
                G.add_edge(entity1, entity2, weight=strength)
            
            # Set up plot
            plt.figure(figsize=(12, 8))
            
            # Calculate node sizes based on degree
            node_sizes = [300 * (1 + G.degree(node)) for node in G.nodes()]
            
            # Calculate edge widths based on weight
            edge_widths = [0.5 + 0.5 * G[u][v].get('weight', 1) for u, v in G.edges()]
            
            # Set node colors
            node_colors = ['skyblue' for _ in G.nodes()]
            
            # Draw the graph
            pos = nx.spring_layout(G, seed=42)  # For reproducibility
            nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color=node_colors, alpha=0.8)
            nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.5, edge_color='gray')
            nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')
            
            # Add title
            plt.title('Entity Connection Graph', fontsize=16)
            
            # Remove axis
            plt.axis('off')
            
            # Save figure
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Graph visualization error: {str(e)}")
            return False
    
    def _generate_comparison_visualization(self, comparison, output_file):
        """Generate a visualization of data comparison results."""
        try:
            # Set up plot
            plt.figure(figsize=(12, 8))
            
            # Create subplots
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
            
            # Plot field comparison (Venn diagram-like)
            common_count = len(comparison['common_fields'])
            unique1_count = len(comparison['unique_fields_data1'])
            unique2_count = len(comparison['unique_fields_data2'])
            
            # Create bar chart for field comparison
            ax1.bar(['Common Fields', 'Unique to Data 1', 'Unique to Data 2'], 
                   [common_count, unique1_count, unique2_count],
                   color=['green', 'blue', 'orange'])
            
            ax1.set_title('Field Comparison')
            ax1.set_ylabel('Number of Fields')
            
            # Add field counts as text
            for i, count in enumerate([common_count, unique1_count, unique2_count]):
                if count > 0:
                    ax1.text(i, count + 0.1, str(count), ha='center')
            
            # Plot similarity score
            similarity = comparison['structure_similarity']
            
            # Create gauge-like visualization for similarity
            ax2.pie([similarity, 100 - similarity], 
                   colors=['green', 'lightgray'],
                   startangle=90,
                   counterclock=False)
            
            # Add a circle at the center to make it look like a gauge
            centre_circle = plt.Circle((0, 0), 0.70, fc='white')
            ax2.add_patch(centre_circle)
            
            # Add similarity percentage text
            ax2.text(0, 0, f"{similarity:.1f}%", ha='center', va='center', fontsize=24)
            
            ax2.set_title('Structure Similarity')
            
            # Add overall title
            fig.suptitle('Data Comparison Results', fontsize=16)
            
            # Adjust layout
            plt.tight_layout()
            
            # Save figure
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Comparison visualization error: {str(e)}")
            return False
    
    def _generate_cross_reference_visualization(self, cross_ref, output_file):
        """Generate a visualization of cross-reference results."""
        try:
            # Extract data
            entities = cross_ref.get('entities', [])
            sources = cross_ref.get('sources', [])
            matches = cross_ref.get('matches', [])
            
            # Create bipartite graph
            B = nx.Graph()
            
            # Add entity nodes
            for entity in entities:
                entity_id = entity.get('id', '')
                B.add_node(entity_id, bipartite=0, node_type='entity')
            
            # Add source nodes
            for source in sources:
                source_id = source.get('id', '')
                B.add_node(source_id, bipartite=1, node_type='source')
            
            # Add edges for matches
            for match in matches:
                entity_id = match.get('entity_id', '')
                source_id = match.get('source_id', '')
                match_score = match.get('match_score', 0)
                
                # Add edge with weight based on match score
                B.add_edge(entity_id, source_id, weight=match_score)
            
            # Set up plot
            plt.figure(figsize=(12, 8))
            
            # Separate nodes by type
            entity_nodes = [n for n, d in B.nodes(data=True) if d['bipartite'] == 0]
            source_nodes = [n for n, d in B.nodes(data=True) if d['bipartite'] == 1]
            
            # Position nodes
            pos = {}
            
            # Position entity nodes on the left
            pos.update((node, (1, i)) for i, node in enumerate(entity_nodes))
            
            # Position source nodes on the right
            pos.update((node, (2, i)) for i, node in enumerate(source_nodes))
            
            # Draw the graph
            nx.draw_networkx_nodes(B, pos, nodelist=entity_nodes, node_color='skyblue', 
                                  node_size=500, alpha=0.8, label='Entities')
            nx.draw_networkx_nodes(B, pos, nodelist=source_nodes, node_color='lightgreen', 
                                  node_size=500, alpha=0.8, label='Sources')
            
            # Draw edges with width based on match score
            edge_widths = [0.5 + 0.05 * B[u][v].get('weight', 0) for u, v in B.edges()]
            nx.draw_networkx_edges(B, pos, width=edge_widths, alpha=0.5, edge_color='gray')
            
            # Draw labels
            nx.draw_networkx_labels(B, pos, font_size=10, font_family='sans-serif')
            
            # Add legend
            plt.legend()
            
            # Add title
            plt.title('Entity-Source Cross-Reference', fontsize=16)
            
            # Remove axis
            plt.axis('off')
            
            # Save figure
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Cross-reference visualization error: {str(e)}")
            return False
    
    def _generate_patterns_visualization(self, patterns, output_file):
        """Generate a visualization of common patterns."""
        try:
            # Extract data
            common_fields = patterns.get('common_fields', [])
            common_values = patterns.get('common_values', [])
            structural_patterns = patterns.get('structural_patterns', [])
            
            # Set up plot
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
            
            # Plot common fields count
            ax1.bar(['Common Fields', 'Fields with Common Values', 'Structural Patterns'], 
                   [len(common_fields), len(common_values), len(structural_patterns)],
                   color=['blue', 'green', 'orange'])
            
            ax1.set_title('Common Pattern Types')
            ax1.set_ylabel('Count')
            
            # Add counts as text
            for i, count in enumerate([len(common_fields), len(common_values), len(structural_patterns)]):
                if count > 0:
                    ax1.text(i, count + 0.1, str(count), ha='center')
            
            # Plot pattern details if available
            if structural_patterns:
                # Group patterns by type
                pattern_types = {}
                for pattern in structural_patterns:
                    pattern_type = pattern.get('type', 'unknown')
                    pattern_types[pattern_type] = pattern_types.get(pattern_type, 0) + 1
                
                # Plot pattern types
                types = list(pattern_types.keys())
                counts = list(pattern_types.values())
                
                ax2.bar(types, counts, color='orange')
                ax2.set_title('Structural Pattern Types')
                ax2.set_ylabel('Count')
                
                # Rotate x-axis labels if needed
                if len(types) > 3:
                    plt.setp(ax2.get_xticklabels(), rotation=45, ha='right')
            else:
                ax2.text(0.5, 0.5, 'No structural patterns found', 
                        ha='center', va='center', transform=ax2.transAxes)
            
            # Add overall title
            fig.suptitle('Common Patterns Analysis', fontsize=16)
            
            # Adjust layout
            plt.tight_layout()
            
            # Save figure
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Patterns visualization error: {str(e)}")
            return False
