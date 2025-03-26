"""
Digital Signatures module for the Ultimate PI Tool.

This module provides functionality for creating and verifying digital signatures
using asymmetric cryptography.
"""

import os
import sys
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from rich.console import Console

console = Console()

class DigitalSignatures:
    """Digital Signatures class for signing and verifying data."""
    
    def __init__(self):
        """Initialize the Digital Signatures module."""
        pass
    
    def sign_file(self, input_file, signature_file, private_key_file):
        """Sign a file using RSA private key."""
        console.print(f"[bold blue]Signing file:[/] [bold green]{input_file}[/]")
        
        try:
            # Read input file
            with open(input_file, 'rb') as f:
                data = f.read()
            
            # Read private key
            with open(private_key_file, 'rb') as f:
                private_key_data = f.read()
            
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )
            
            # Create signature
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Save signature to file
            with open(signature_file, 'wb') as f:
                f.write(signature)
            
            console.print(f"[bold green]Success![/] Signature saved to: [bold]{signature_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def verify_file(self, input_file, signature_file, public_key_file):
        """Verify a file signature using RSA public key."""
        console.print(f"[bold blue]Verifying signature for file:[/] [bold green]{input_file}[/]")
        
        try:
            # Read input file
            with open(input_file, 'rb') as f:
                data = f.read()
            
            # Read signature
            with open(signature_file, 'rb') as f:
                signature = f.read()
            
            # Read public key
            with open(public_key_file, 'rb') as f:
                public_key_data = f.read()
            
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_data,
                backend=default_backend()
            )
            
            # Verify signature
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            console.print(f"[bold green]Success![/] Signature verified")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] Signature verification failed: {str(e)}")
            return False
    
    def sign_data(self, data, private_key_data):
        """Sign data using RSA private key."""
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )
            
            # Create signature
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return signature
            
        except Exception as e:
            raise Exception(f"Signing failed: {str(e)}")
    
    def verify_data(self, data, signature, public_key_data):
        """Verify data signature using RSA public key."""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_data,
                backend=default_backend()
            )
            
            # Verify signature
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            raise Exception(f"Verification failed: {str(e)}")
    
    def create_detached_signature(self, input_file, signature_file, private_key_file, algorithm='sha256'):
        """Create a detached signature for a file."""
        console.print(f"[bold blue]Creating detached signature for file:[/] [bold green]{input_file}[/]")
        
        try:
            # Read private key
            with open(private_key_file, 'rb') as f:
                private_key_data = f.read()
            
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )
            
            # Calculate file hash
            hash_algorithm = getattr(hashes, algorithm.upper())()
            hasher = hashes.Hash(hash_algorithm, default_backend())
            
            with open(input_file, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            
            digest = hasher.finalize()
            
            # Create signature
            signature = private_key.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hash_algorithm)
            )
            
            # Save signature to file
            with open(signature_file, 'wb') as f:
                f.write(signature)
            
            console.print(f"[bold green]Success![/] Detached signature saved to: [bold]{signature_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def verify_detached_signature(self, input_file, signature_file, public_key_file, algorithm='sha256'):
        """Verify a detached signature for a file."""
        console.print(f"[bold blue]Verifying detached signature for file:[/] [bold green]{input_file}[/]")
        
        try:
            # Read signature
            with open(signature_file, 'rb') as f:
                signature = f.read()
            
            # Read public key
            with open(public_key_file, 'rb') as f:
                public_key_data = f.read()
            
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_data,
                backend=default_backend()
            )
            
            # Calculate file hash
            hash_algorithm = getattr(hashes, algorithm.upper())()
            hasher = hashes.Hash(hash_algorithm, default_backend())
            
            with open(input_file, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            
            digest = hasher.finalize()
            
            # Verify signature
            public_key.verify(
                signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hash_algorithm)
            )
            
            console.print(f"[bold green]Success![/] Detached signature verified")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] Signature verification failed: {str(e)}")
            return False
