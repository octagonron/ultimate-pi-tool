"""
Hashing Functions module for the Ultimate PI Tool.

This module provides functionality for various hashing algorithms
including SHA-256, SHA-512, MD5, and more.
"""

import os
import sys
import hashlib
import binascii
from rich.console import Console
from rich.table import Table

console = Console()

class HashingFunctions:
    """Hashing Functions class for file and text hashing."""
    
    def __init__(self):
        """Initialize the Hashing Functions module."""
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s
        }
    
    def hash_file(self, file_path, algorithm='sha256', display=True):
        """Calculate hash of a file using the specified algorithm."""
        if display:
            console.print(f"[bold blue]Calculating {algorithm.upper()} hash of file:[/] [bold green]{file_path}[/]")
        
        try:
            # Check if algorithm is supported
            if algorithm.lower() not in self.supported_algorithms:
                if display:
                    console.print(f"[bold red]Error:[/] Unsupported algorithm: {algorithm}")
                    console.print(f"[bold blue]Supported algorithms:[/] {', '.join(self.supported_algorithms.keys())}")
                return None
            
            # Get hash function
            hash_func = self.supported_algorithms[algorithm.lower()]()
            
            # Calculate hash
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            
            # Get hash digest
            hash_digest = hash_func.digest()
            hash_hex = hash_func.hexdigest()
            
            if display:
                console.print(f"[bold green]{algorithm.upper()} hash:[/] {hash_hex}")
            
            return hash_hex
            
        except Exception as e:
            if display:
                console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def hash_text(self, text, algorithm='sha256', display=True):
        """Calculate hash of text using the specified algorithm."""
        if display:
            console.print(f"[bold blue]Calculating {algorithm.upper()} hash of text[/]")
        
        try:
            # Check if algorithm is supported
            if algorithm.lower() not in self.supported_algorithms:
                if display:
                    console.print(f"[bold red]Error:[/] Unsupported algorithm: {algorithm}")
                    console.print(f"[bold blue]Supported algorithms:[/] {', '.join(self.supported_algorithms.keys())}")
                return None
            
            # Get hash function
            hash_func = self.supported_algorithms[algorithm.lower()]()
            
            # Convert text to bytes if necessary
            if isinstance(text, str):
                text = text.encode('utf-8')
            
            # Calculate hash
            hash_func.update(text)
            
            # Get hash digest
            hash_digest = hash_func.digest()
            hash_hex = hash_func.hexdigest()
            
            if display:
                console.print(f"[bold green]{algorithm.upper()} hash:[/] {hash_hex}")
            
            return hash_hex
            
        except Exception as e:
            if display:
                console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def hash_directory(self, directory_path, algorithm='sha256', recursive=True):
        """Calculate hashes of all files in a directory."""
        console.print(f"[bold blue]Calculating {algorithm.upper()} hashes of files in directory:[/] [bold green]{directory_path}[/]")
        
        try:
            # Check if directory exists
            if not os.path.isdir(directory_path):
                console.print(f"[bold red]Error:[/] Directory not found: {directory_path}")
                return None
            
            # Create table for results
            table = Table(title=f"{algorithm.upper()} File Hashes")
            table.add_column("File", style="cyan")
            table.add_column("Hash", style="green")
            
            # Dictionary to store results
            results = {}
            
            # Walk through directory
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, directory_path)
                        hash_value = self.hash_file(file_path, algorithm, display=False)
                        if hash_value:
                            results[relative_path] = hash_value
                            table.add_row(relative_path, hash_value)
            else:
                for file in os.listdir(directory_path):
                    file_path = os.path.join(directory_path, file)
                    if os.path.isfile(file_path):
                        hash_value = self.hash_file(file_path, algorithm, display=False)
                        if hash_value:
                            results[file] = hash_value
                            table.add_row(file, hash_value)
            
            # Display results
            console.print(table)
            
            return results
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def verify_file_hash(self, file_path, expected_hash, algorithm='sha256'):
        """Verify if a file matches an expected hash."""
        console.print(f"[bold blue]Verifying {algorithm.upper()} hash of file:[/] [bold green]{file_path}[/]")
        
        try:
            # Calculate file hash
            file_hash = self.hash_file(file_path, algorithm, display=False)
            
            if not file_hash:
                console.print(f"[bold red]Error:[/] Failed to calculate hash")
                return False
            
            # Compare hashes (case-insensitive)
            if file_hash.lower() == expected_hash.lower():
                console.print(f"[bold green]Hash verification successful![/]")
                console.print(f"Expected: {expected_hash.lower()}")
                console.print(f"Actual:   {file_hash.lower()}")
                return True
            else:
                console.print(f"[bold red]Hash verification failed![/]")
                console.print(f"Expected: {expected_hash.lower()}")
                console.print(f"Actual:   {file_hash.lower()}")
                return False
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def list_algorithms(self):
        """List supported hashing algorithms."""
        console.print("[bold blue]Supported Hashing Algorithms:[/]")
        for algorithm in self.supported_algorithms.keys():
            console.print(f"- {algorithm.upper()}")
        return list(self.supported_algorithms.keys())
