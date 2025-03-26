"""
Key Management module for the Ultimate PI Tool.

This module provides functionality for generating, managing, and using
cryptographic keys for various algorithms.
"""

import os
import sys
import json
import base64
import datetime
import secrets
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import load_pem_x509_certificate
from cryptography import x509
from cryptography.x509.oid import NameOID
import cryptography.exceptions

console = Console()

class KeyManager:
    """Key Manager class for generating and managing cryptographic keys."""
    
    def __init__(self, keys_dir=None):
        """Initialize the Key Manager module."""
        # Set keys directory
        if keys_dir:
            self.keys_dir = Path(keys_dir)
        else:
            self.keys_dir = Path.home() / ".pi_tool" / "keys"
        
        # Create directory if it doesn't exist
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize key store
        self.key_store_file = self.keys_dir / "key_store.json"
        self.key_store = self._load_key_store()
    
    def generate_rsa_key_pair(self, name, key_size=2048, password=None, overwrite=False):
        """Generate an RSA key pair."""
        console.print(f"[bold blue]Generating RSA key pair:[/] {name}")
        
        # Check if key already exists
        if name in self.key_store and not overwrite:
            console.print(f"[bold red]Error:[/] Key with name '{name}' already exists. Use overwrite=True to replace it.")
            return False
        
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            if password:
                # Encrypt private key with password
                encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption_algorithm = serialization.NoEncryption()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Save keys to files
            private_key_file = self.keys_dir / f"{name}_rsa_private.pem"
            public_key_file = self.keys_dir / f"{name}_rsa_public.pem"
            
            with open(private_key_file, 'wb') as f:
                f.write(private_pem)
            
            with open(public_key_file, 'wb') as f:
                f.write(public_pem)
            
            # Update key store
            self.key_store[name] = {
                "type": "rsa",
                "key_size": key_size,
                "private_key_file": str(private_key_file),
                "public_key_file": str(public_key_file),
                "password_protected": password is not None,
                "created_at": datetime.datetime.now().isoformat()
            }
            
            self._save_key_store()
            
            console.print(f"[bold green]RSA key pair generated successfully![/]")
            console.print(f"[bold green]Private key saved to:[/] {private_key_file}")
            console.print(f"[bold green]Public key saved to:[/] {public_key_file}")
            
            # Display key fingerprint
            fingerprint = self.get_key_fingerprint(name)
            console.print(f"[bold green]Key fingerprint:[/] {fingerprint}")
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error generating RSA key pair:[/] {str(e)}")
            return False
    
    def generate_ec_key_pair(self, name, curve="secp256r1", password=None, overwrite=False):
        """Generate an Elliptic Curve key pair."""
        console.print(f"[bold blue]Generating EC key pair:[/] {name}")
        
        # Check if key already exists
        if name in self.key_store and not overwrite:
            console.print(f"[bold red]Error:[/] Key with name '{name}' already exists. Use overwrite=True to replace it.")
            return False
        
        try:
            # Determine curve
            if curve == "secp256r1":
                curve_obj = ec.SECP256R1()
            elif curve == "secp384r1":
                curve_obj = ec.SECP384R1()
            elif curve == "secp521r1":
                curve_obj = ec.SECP521R1()
            else:
                console.print(f"[bold red]Error:[/] Unsupported curve: {curve}")
                return False
            
            # Generate private key
            private_key = ec.generate_private_key(curve_obj)
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            if password:
                # Encrypt private key with password
                encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption_algorithm = serialization.NoEncryption()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Save keys to files
            private_key_file = self.keys_dir / f"{name}_ec_private.pem"
            public_key_file = self.keys_dir / f"{name}_ec_public.pem"
            
            with open(private_key_file, 'wb') as f:
                f.write(private_pem)
            
            with open(public_key_file, 'wb') as f:
                f.write(public_pem)
            
            # Update key store
            self.key_store[name] = {
                "type": "ec",
                "curve": curve,
                "private_key_file": str(private_key_file),
                "public_key_file": str(public_key_file),
                "password_protected": password is not None,
                "created_at": datetime.datetime.now().isoformat()
            }
            
            self._save_key_store()
            
            console.print(f"[bold green]EC key pair generated successfully![/]")
            console.print(f"[bold green]Private key saved to:[/] {private_key_file}")
            console.print(f"[bold green]Public key saved to:[/] {public_key_file}")
            
            # Display key fingerprint
            fingerprint = self.get_key_fingerprint(name)
            console.print(f"[bold green]Key fingerprint:[/] {fingerprint}")
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error generating EC key pair:[/] {str(e)}")
            return False
    
    def generate_symmetric_key(self, name, key_size=256, overwrite=False):
        """Generate a symmetric key."""
        console.print(f"[bold blue]Generating symmetric key:[/] {name}")
        
        # Check if key already exists
        if name in self.key_store and not overwrite:
            console.print(f"[bold red]Error:[/] Key with name '{name}' already exists. Use overwrite=True to replace it.")
            return False
        
        try:
            # Generate random key
            key_bytes = secrets.token_bytes(key_size // 8)
            
            # Encode key in Base64
            key_b64 = base64.b64encode(key_bytes).decode('utf-8')
            
            # Save key to file
            key_file = self.keys_dir / f"{name}_symmetric.key"
            
            with open(key_file, 'w') as f:
                f.write(key_b64)
            
            # Update key store
            self.key_store[name] = {
                "type": "symmetric",
                "key_size": key_size,
                "key_file": str(key_file),
                "created_at": datetime.datetime.now().isoformat()
            }
            
            self._save_key_store()
            
            console.print(f"[bold green]Symmetric key generated successfully![/]")
            console.print(f"[bold green]Key saved to:[/] {key_file}")
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error generating symmetric key:[/] {str(e)}")
            return False
    
    def import_key(self, name, key_file, key_type="auto", password=None, overwrite=False):
        """Import an existing key."""
        console.print(f"[bold blue]Importing key:[/] {name}")
        
        # Check if key already exists
        if name in self.key_store and not overwrite:
            console.print(f"[bold red]Error:[/] Key with name '{name}' already exists. Use overwrite=True to replace it.")
            return False
        
        try:
            # Read key file
            with open(key_file, 'rb') as f:
                key_data = f.read()
            
            # Determine key type if auto
            if key_type == "auto":
                if b"-----BEGIN PRIVATE KEY-----" in key_data or b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in key_data:
                    key_type = "private"
                elif b"-----BEGIN PUBLIC KEY-----" in key_data:
                    key_type = "public"
                elif b"-----BEGIN CERTIFICATE-----" in key_data:
                    key_type = "certificate"
                else:
                    # Try to decode as Base64
                    try:
                        base64.b64decode(key_data)
                        key_type = "symmetric"
                    except:
                        console.print(f"[bold red]Error:[/] Could not determine key type. Please specify key_type parameter.")
                        return False
            
            # Process key based on type
            if key_type == "private":
                # Try to load private key
                try:
                    if password:
                        private_key = load_pem_private_key(key_data, password.encode())
                    else:
                        private_key = load_pem_private_key(key_data, None)
                    
                    # Determine algorithm type
                    if isinstance(private_key, rsa.RSAPrivateKey):
                        algo_type = "rsa"
                        key_size = private_key.key_size
                    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                        algo_type = "ec"
                        curve = private_key.curve.name
                    else:
                        console.print(f"[bold red]Error:[/] Unsupported private key type.")
                        return False
                    
                    # Get public key
                    public_key = private_key.public_key()
                    
                    # Serialize public key
                    public_pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    
                    # Save keys to files
                    private_key_file = self.keys_dir / f"{name}_{algo_type}_private.pem"
                    public_key_file = self.keys_dir / f"{name}_{algo_type}_public.pem"
                    
                    with open(private_key_file, 'wb') as f:
                        f.write(key_data)
                    
                    with open(public_key_file, 'wb') as f:
                        f.write(public_pem)
                    
                    # Update key store
                    if algo_type == "rsa":
                        self.key_store[name] = {
                            "type": "rsa",
                            "key_size": key_size,
                            "private_key_file": str(private_key_file),
                            "public_key_file": str(public_key_file),
                            "password_protected": password is not None,
                            "created_at": datetime.datetime.now().isoformat(),
                            "imported": True
                        }
                    else:  # EC
                        self.key_store[name] = {
                            "type": "ec",
                            "curve": curve,
                            "private_key_file": str(private_key_file),
                            "public_key_file": str(public_key_file),
                            "password_protected": password is not None,
                            "created_at": datetime.datetime.now().isoformat(),
                            "imported": True
                        }
                    
                    console.print(f"[bold green]Private key imported successfully![/]")
                    console.print(f"[bold green]Private key saved to:[/] {private_key_file}")
                    console.print(f"[bold green]Public key saved to:[/] {public_key_file}")
                    
                except Exception as e:
                    console.print(f"[bold red]Error loading private key:[/] {str(e)}")
                    return False
                
            elif key_type == "public":
                # Try to load public key
                try:
                    public_key = load_pem_public_key(key_data)
                    
                    # Determine algorithm type
                    if isinstance(public_key, rsa.RSAPublicKey):
                        algo_type = "rsa"
                        key_size = public_key.key_size
                    elif isinstance(public_key, ec.EllipticCurvePublicKey):
                        algo_type = "ec"
                        curve = public_key.curve.name
                    else:
                        console.print(f"[bold red]Error:[/] Unsupported public key type.")
                        return False
                    
                    # Save key to file
                    public_key_file = self.keys_dir / f"{name}_{algo_type}_public.pem"
                    
                    with open(public_key_file, 'wb') as f:
                        f.write(key_data)
                    
                    # Update key store
                    if algo_type == "rsa":
                        self.key_store[name] = {
                            "type": "rsa",
                            "key_size": key_size,
                            "public_key_file": str(public_key_file),
                            "created_at": datetime.datetime.now().isoformat(),
                            "imported": True,
                            "public_only": True
                        }
                    else:  # EC
                        self.key_store[name] = {
                            "type": "ec",
                            "curve": curve,
                            "public_key_file": str(public_key_file),
                            "created_at": datetime.datetime.now().isoformat(),
                            "imported": True,
                            "public_only": True
                        }
                    
                    console.print(f"[bold green]Public key imported successfully![/]")
                    console.print(f"[bold green]Public key saved to:[/] {public_key_file}")
                    
                except Exception as e:
                    console.print(f"[bold red]Error loading public key:[/] {str(e)}")
                    return False
                
            elif key_type == "certificate":
                # Try to load certificate
                try:
                    cert = load_pem_x509_certificate(key_data)
                    
                    # Extract public key
                    public_key = cert.public_key()
                    
                    # Determine algorithm type
                    if isinstance(public_key, rsa.RSAPublicKey):
                        algo_type = "rsa"
                        key_size = public_key.key_size
                    elif isinstance(public_key, ec.EllipticCurvePublicKey):
                        algo_type = "ec"
                        curve = public_key.curve.name
                    else:
                        console.print(f"[bold red]Error:[/] Unsupported certificate key type.")
                        return False
                    
                    # Serialize public key
                    public_pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    
                    # Save certificate and public key to files
                    cert_file = self.keys_dir / f"{name}_certificate.pem"
                    public_key_file = self.keys_dir / f"{name}_{algo_type}_public.pem"
                    
                    with open(cert_file, 'wb') as f:
                        f.write(key_data)
                    
                    with open(public_key_file, 'wb') as f:
                        f.write(public_pem)
                    
                    # Update key store
                    if algo_type == "rsa":
                        self.key_store[name] = {
                            "type": "rsa",
                            "key_size": key_size,
                            "certificate_file": str(cert_file),
                            "public_key_file": str(public_key_file),
                            "created_at": datetime.datetime.now().isoformat(),
                            "imported": True,
                            "public_only": True
                        }
                    else:  # EC
                        self.key_store[name] = {
                            "type": "ec",
                            "curve": curve,
                            "certificate_file": str(cert_file),
                            "public_key_file": str(public_key_file),
                            "created_at": datetime.datetime.now().isoformat(),
                            "imported": True,
                            "public_only": True
                        }
                    
                    console.print(f"[bold green]Certificate imported successfully![/]")
                    console.print(f"[bold green]Certificate saved to:[/] {cert_file}")
                    console.print(f"[bold green]Public key saved to:[/] {public_key_file}")
                    
                except Exception as e:
                    console.print(f"[bold red]Error loading certificate:[/] {str(e)}")
                    return False
                
            elif key_type == "symmetric":
                # Try to decode as Base64
                try:
                    key_bytes = base64.b64decode(key_data)
                    key_size = len(key_bytes) * 8
                    
                    # Save key to file
                    key_file = self.keys_dir / f"{name}_symmetric.key"
                    
                    with open(key_file, 'wb') as f:
                        f.write(key_data)
                    
                    # Update key store
                    self.key_store[name] = {
                        "type": "symmetric",
                        "key_size": key_size,
                        "key_file": str(key_file),
                        "created_at": datetime.datetime.now().isoformat(),
                        "imported": True
                    }
                    
                    console.print(f"[bold green]Symmetric key imported successfully![/]")
                    console.print(f"[bold green]Key saved to:[/] {key_file}")
                    
                except Exception as e:
                    console.print(f"[bold red]Error importing symmetric key:[/] {str(e)}")
                    return False
            
            else:
                console.print(f"[bold red]Error:[/] Unsupported key type: {key_type}")
                return False
            
            self._save_key_store()
            
            # Display key fingerprint
            fingerprint = self.get_key_fingerprint(name)
            if fingerprint:
                console.print(f"[bold green]Key fingerprint:[/] {fingerprint}")
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error importing key:[/] {str(e)}")
            return False
    
    def export_key(self, name, output_file=None, key_type="private", password=None):
        """Export a key to a file."""
        console.print(f"[bold blue]Exporting key:[/] {name}")
        
        # Check if key exists
        if name not in self.key_store:
            console.print(f"[bold red]Error:[/] Key with name '{name}' not found.")
            return False
        
        try:
            key_info = self.key_store[name]
            
            # Determine source file based on key type
            if key_type == "private":
                if "private_key_file" not in key_info:
                    console.print(f"[bold red]Error:[/] No private key available for '{name}'.")
                    return False
                
                source_file = key_info["private_key_file"]
                
                # Check if key is password protected and no password provided
                if key_info.get("password_protected", False) and not password:
                    console.print(f"[bold red]Error:[/] Key is password protected. Please provide the password.")
                    return False
                
            elif key_type == "public":
                if "public_key_file" not in key_info:
                    console.print(f"[bold red]Error:[/] No public key available for '{name}'.")
                    return False
                
                source_file = key_info["public_key_file"]
                
            elif key_type == "certificate":
                if "certificate_file" not in key_info:
                    console.print(f"[bold red]Error:[/] No certificate available for '{name}'.")
                    return False
                
                source_file = key_info["certificate_file"]
                
            elif key_type == "symmetric":
                if key_info["type"] != "symmetric":
                    console.print(f"[bold red]Error:[/] Key '{name}' is not a symmetric key.")
                    return False
                
                source_file = key_info["key_file"]
                
            else:
                console.print(f"[bold red]Error:[/] Unsupported key type: {key_type}")
                return False
            
            # Determine output file if not provided
            if not output_file:
                output_file = f"{name}_{key_type}.pem"
            
            # Copy key to output file
            with open(source_file, 'rb') as src:
                with open(output_file, 'wb') as dst:
                    dst.write(src.read())
            
            console.print(f"[bold green]Key exported successfully to:[/] {output_file}")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error exporting key:[/] {str(e)}")
            return False
    
    def delete_key(self, name):
        """Delete a key."""
        console.print(f"[bold blue]Deleting key:[/] {name}")
        
        # Check if key exists
        if name not in self.key_store:
            console.print(f"[bold red]Error:[/] Key with name '{name}' not found.")
            return False
        
        try:
            key_info = self.key_store[name]
            
            # Delete key files
            if "private_key_file" in key_info:
                private_key_file = key_info["private_key_file"]
                if os.path.exists(private_key_file):
                    os.remove(private_key_file)
            
            if "public_key_file" in key_info:
                public_key_file = key_info["public_key_file"]
                if os.path.exists(public_key_file):
                    os.remove(public_key_file)
            
            if "certificate_file" in key_info:
                cert_file = key_info["certificate_file"]
                if os.path.exists(cert_file):
                    os.remove(cert_file)
            
            if "key_file" in key_info:
                key_file = key_info["key_file"]
                if os.path.exists(key_file):
                    os.remove(key_file)
            
            # Remove from key store
            del self.key_store[name]
            self._save_key_store()
            
            console.print(f"[bold green]Key deleted successfully![/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error deleting key:[/] {str(e)}")
            return False
    
    def list_keys(self):
        """List all keys in the key store."""
        console.print(f"[bold blue]Listing keys[/]")
        
        if not self.key_store:
            console.print("[bold yellow]No keys found.[/]")
            return []
        
        # Create table
        table = Table(title="Key Store")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Details", style="yellow")
        table.add_column("Created", style="magenta")
        table.add_column("Fingerprint", style="blue")
        
        for name, key_info in self.key_store.items():
            key_type = key_info["type"]
            
            if key_type == "rsa":
                details = f"RSA {key_info.get('key_size', 'Unknown')} bits"
                if key_info.get("public_only", False):
                    details += " (Public Only)"
                elif key_info.get("password_protected", False):
                    details += " (Password Protected)"
            elif key_type == "ec":
                details = f"EC {key_info.get('curve', 'Unknown')}"
                if key_info.get("public_only", False):
                    details += " (Public Only)"
                elif key_info.get("password_protected", False):
                    details += " (Password Protected)"
            elif key_type == "symmetric":
                details = f"Symmetric {key_info.get('key_size', 'Unknown')} bits"
            else:
                details = "Unknown"
            
            created = key_info.get("created_at", "Unknown")
            if created != "Unknown":
                try:
                    created_dt = datetime.datetime.fromisoformat(created)
                    created = created_dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    pass
            
            fingerprint = self.get_key_fingerprint(name)
            
            table.add_row(name, key_type.upper(), details, created, fingerprint or "N/A")
        
        console.print(table)
        
        return list(self.key_store.keys())
    
    def get_key_info(self, name):
        """Get detailed information about a key."""
        console.print(f"[bold blue]Getting key info:[/] {name}")
        
        # Check if key exists
        if name not in self.key_store:
            console.print(f"[bold red]Error:[/] Key with name '{name}' not found.")
            return None
        
        try:
            key_info = self.key_store[name]
            key_type = key_info["type"]
            
            # Create panel with key info
            if key_type == "rsa":
                # Load public key to get more details
                public_key_file = key_info.get("public_key_file")
                if public_key_file and os.path.exists(public_key_file):
                    with open(public_key_file, 'rb') as f:
                        public_key = load_pem_public_key(f.read())
                    
                    key_size = public_key.key_size
                    public_numbers = public_key.public_numbers()
                    
                    details = f"""
[bold]Key Type:[/] RSA
[bold]Key Size:[/] {key_size} bits
[bold]Public Exponent:[/] {public_numbers.e}
[bold]Public Only:[/] {key_info.get("public_only", False)}
[bold]Password Protected:[/] {key_info.get("password_protected", False)}
[bold]Created:[/] {key_info.get("created_at", "Unknown")}
[bold]Imported:[/] {key_info.get("imported", False)}
[bold]Fingerprint:[/] {self.get_key_fingerprint(name) or "N/A"}
[bold]Public Key File:[/] {public_key_file}
"""
                    
                    if "private_key_file" in key_info:
                        details += f"[bold]Private Key File:[/] {key_info['private_key_file']}\n"
                    
                    if "certificate_file" in key_info:
                        details += f"[bold]Certificate File:[/] {key_info['certificate_file']}\n"
                    
                    panel = Panel(details, title=f"RSA Key: {name}", border_style="green")
                    console.print(panel)
                    
                    return {
                        "name": name,
                        "type": "rsa",
                        "key_size": key_size,
                        "public_exponent": public_numbers.e,
                        "public_only": key_info.get("public_only", False),
                        "password_protected": key_info.get("password_protected", False),
                        "created_at": key_info.get("created_at", "Unknown"),
                        "imported": key_info.get("imported", False),
                        "fingerprint": self.get_key_fingerprint(name),
                        "public_key_file": public_key_file,
                        "private_key_file": key_info.get("private_key_file"),
                        "certificate_file": key_info.get("certificate_file")
                    }
                
            elif key_type == "ec":
                # Load public key to get more details
                public_key_file = key_info.get("public_key_file")
                if public_key_file and os.path.exists(public_key_file):
                    with open(public_key_file, 'rb') as f:
                        public_key = load_pem_public_key(f.read())
                    
                    curve = public_key.curve.name
                    
                    details = f"""
[bold]Key Type:[/] Elliptic Curve
[bold]Curve:[/] {curve}
[bold]Public Only:[/] {key_info.get("public_only", False)}
[bold]Password Protected:[/] {key_info.get("password_protected", False)}
[bold]Created:[/] {key_info.get("created_at", "Unknown")}
[bold]Imported:[/] {key_info.get("imported", False)}
[bold]Fingerprint:[/] {self.get_key_fingerprint(name) or "N/A"}
[bold]Public Key File:[/] {public_key_file}
"""
                    
                    if "private_key_file" in key_info:
                        details += f"[bold]Private Key File:[/] {key_info['private_key_file']}\n"
                    
                    if "certificate_file" in key_info:
                        details += f"[bold]Certificate File:[/] {key_info['certificate_file']}\n"
                    
                    panel = Panel(details, title=f"EC Key: {name}", border_style="green")
                    console.print(panel)
                    
                    return {
                        "name": name,
                        "type": "ec",
                        "curve": curve,
                        "public_only": key_info.get("public_only", False),
                        "password_protected": key_info.get("password_protected", False),
                        "created_at": key_info.get("created_at", "Unknown"),
                        "imported": key_info.get("imported", False),
                        "fingerprint": self.get_key_fingerprint(name),
                        "public_key_file": public_key_file,
                        "private_key_file": key_info.get("private_key_file"),
                        "certificate_file": key_info.get("certificate_file")
                    }
                
            elif key_type == "symmetric":
                key_file = key_info.get("key_file")
                key_size = key_info.get("key_size", "Unknown")
                
                details = f"""
[bold]Key Type:[/] Symmetric
[bold]Key Size:[/] {key_size} bits
[bold]Created:[/] {key_info.get("created_at", "Unknown")}
[bold]Imported:[/] {key_info.get("imported", False)}
[bold]Key File:[/] {key_file}
"""
                
                panel = Panel(details, title=f"Symmetric Key: {name}", border_style="green")
                console.print(panel)
                
                return {
                    "name": name,
                    "type": "symmetric",
                    "key_size": key_size,
                    "created_at": key_info.get("created_at", "Unknown"),
                    "imported": key_info.get("imported", False),
                    "key_file": key_file
                }
            
            # Fallback for unknown key types
            console.print(f"[bold yellow]Key info:[/] {key_info}")
            return key_info
            
        except Exception as e:
            console.print(f"[bold red]Error getting key info:[/] {str(e)}")
            return None
    
    def get_key_fingerprint(self, name):
        """Get the fingerprint of a key."""
        # Check if key exists
        if name not in self.key_store:
            return None
        
        try:
            key_info = self.key_store[name]
            key_type = key_info["type"]
            
            if key_type in ["rsa", "ec"]:
                # Load public key
                public_key_file = key_info.get("public_key_file")
                if public_key_file and os.path.exists(public_key_file):
                    with open(public_key_file, 'rb') as f:
                        public_key = load_pem_public_key(f.read())
                    
                    # Get DER encoding
                    der_data = public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    
                    # Calculate SHA-256 fingerprint
                    digest = hashes.Hash(hashes.SHA256())
                    digest.update(der_data)
                    fingerprint_bytes = digest.finalize()
                    
                    # Format fingerprint
                    fingerprint = ":".join([f"{b:02X}" for b in fingerprint_bytes[:8]])
                    
                    return fingerprint
            
            elif key_type == "symmetric":
                # Load symmetric key
                key_file = key_info.get("key_file")
                if key_file and os.path.exists(key_file):
                    with open(key_file, 'rb') as f:
                        key_data = f.read()
                    
                    # Calculate SHA-256 fingerprint
                    digest = hashes.Hash(hashes.SHA256())
                    digest.update(key_data)
                    fingerprint_bytes = digest.finalize()
                    
                    # Format fingerprint
                    fingerprint = ":".join([f"{b:02X}" for b in fingerprint_bytes[:8]])
                    
                    return fingerprint
            
            return None
            
        except Exception:
            return None
    
    def encrypt_with_public_key(self, name, data, output_file=None):
        """Encrypt data using a public key."""
        console.print(f"[bold blue]Encrypting data with public key:[/] {name}")
        
        # Check if key exists
        if name not in self.key_store:
            console.print(f"[bold red]Error:[/] Key with name '{name}' not found.")
            return False
        
        try:
            key_info = self.key_store[name]
            key_type = key_info["type"]
            
            if key_type not in ["rsa", "ec"]:
                console.print(f"[bold red]Error:[/] Key '{name}' is not an asymmetric key.")
                return False
            
            # Load public key
            public_key_file = key_info.get("public_key_file")
            if not public_key_file or not os.path.exists(public_key_file):
                console.print(f"[bold red]Error:[/] Public key file not found.")
                return False
            
            with open(public_key_file, 'rb') as f:
                public_key = load_pem_public_key(f.read())
            
            # Convert data to bytes if it's a string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Encrypt data
            if key_type == "rsa":
                ciphertext = public_key.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            elif key_type == "ec":
                # EC keys can't encrypt directly, use ECDH key exchange
                console.print(f"[bold red]Error:[/] EC keys cannot be used for direct encryption. Use RSA keys instead.")
                return False
            
            # Encode ciphertext in Base64
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
            
            # Save to file if output file is provided
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(ciphertext_b64)
                
                console.print(f"[bold green]Encrypted data saved to:[/] {output_file}")
            
            return ciphertext_b64
            
        except Exception as e:
            console.print(f"[bold red]Error encrypting data:[/] {str(e)}")
            return False
    
    def decrypt_with_private_key(self, name, ciphertext, password=None):
        """Decrypt data using a private key."""
        console.print(f"[bold blue]Decrypting data with private key:[/] {name}")
        
        # Check if key exists
        if name not in self.key_store:
            console.print(f"[bold red]Error:[/] Key with name '{name}' not found.")
            return False
        
        try:
            key_info = self.key_store[name]
            key_type = key_info["type"]
            
            if key_type not in ["rsa", "ec"]:
                console.print(f"[bold red]Error:[/] Key '{name}' is not an asymmetric key.")
                return False
            
            # Check if private key is available
            if "private_key_file" not in key_info:
                console.print(f"[bold red]Error:[/] No private key available for '{name}'.")
                return False
            
            # Check if key is password protected and no password provided
            if key_info.get("password_protected", False) and not password:
                console.print(f"[bold red]Error:[/] Key is password protected. Please provide the password.")
                return False
            
            # Load private key
            private_key_file = key_info["private_key_file"]
            with open(private_key_file, 'rb') as f:
                private_key_data = f.read()
            
            if password:
                private_key = load_pem_private_key(private_key_data, password.encode())
            else:
                private_key = load_pem_private_key(private_key_data, None)
            
            # Decode Base64 ciphertext if it's a string
            if isinstance(ciphertext, str):
                ciphertext = base64.b64decode(ciphertext)
            
            # Decrypt data
            if key_type == "rsa":
                plaintext = private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            elif key_type == "ec":
                # EC keys can't decrypt directly
                console.print(f"[bold red]Error:[/] EC keys cannot be used for direct decryption. Use RSA keys instead.")
                return False
            
            # Try to decode as UTF-8
            try:
                plaintext_str = plaintext.decode('utf-8')
                return plaintext_str
            except:
                return plaintext
            
        except Exception as e:
            console.print(f"[bold red]Error decrypting data:[/] {str(e)}")
            return False
    
    def sign_data(self, name, data, password=None):
        """Sign data using a private key."""
        console.print(f"[bold blue]Signing data with private key:[/] {name}")
        
        # Check if key exists
        if name not in self.key_store:
            console.print(f"[bold red]Error:[/] Key with name '{name}' not found.")
            return False
        
        try:
            key_info = self.key_store[name]
            key_type = key_info["type"]
            
            if key_type not in ["rsa", "ec"]:
                console.print(f"[bold red]Error:[/] Key '{name}' is not an asymmetric key.")
                return False
            
            # Check if private key is available
            if "private_key_file" not in key_info:
                console.print(f"[bold red]Error:[/] No private key available for '{name}'.")
                return False
            
            # Check if key is password protected and no password provided
            if key_info.get("password_protected", False) and not password:
                console.print(f"[bold red]Error:[/] Key is password protected. Please provide the password.")
                return False
            
            # Load private key
            private_key_file = key_info["private_key_file"]
            with open(private_key_file, 'rb') as f:
                private_key_data = f.read()
            
            if password:
                private_key = load_pem_private_key(private_key_data, password.encode())
            else:
                private_key = load_pem_private_key(private_key_data, None)
            
            # Convert data to bytes if it's a string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Sign data
            if key_type == "rsa":
                signature = private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            elif key_type == "ec":
                signature = private_key.sign(
                    data,
                    ec.ECDSA(hashes.SHA256())
                )
            
            # Encode signature in Base64
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            return signature_b64
            
        except Exception as e:
            console.print(f"[bold red]Error signing data:[/] {str(e)}")
            return False
    
    def verify_signature(self, name, data, signature):
        """Verify a signature using a public key."""
        console.print(f"[bold blue]Verifying signature with public key:[/] {name}")
        
        # Check if key exists
        if name not in self.key_store:
            console.print(f"[bold red]Error:[/] Key with name '{name}' not found.")
            return False
        
        try:
            key_info = self.key_store[name]
            key_type = key_info["type"]
            
            if key_type not in ["rsa", "ec"]:
                console.print(f"[bold red]Error:[/] Key '{name}' is not an asymmetric key.")
                return False
            
            # Load public key
            public_key_file = key_info.get("public_key_file")
            if not public_key_file or not os.path.exists(public_key_file):
                console.print(f"[bold red]Error:[/] Public key file not found.")
                return False
            
            with open(public_key_file, 'rb') as f:
                public_key = load_pem_public_key(f.read())
            
            # Convert data to bytes if it's a string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Decode Base64 signature if it's a string
            if isinstance(signature, str):
                signature = base64.b64decode(signature)
            
            # Verify signature
            if key_type == "rsa":
                try:
                    public_key.verify(
                        signature,
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    console.print(f"[bold green]Signature verified successfully![/]")
                    return True
                except cryptography.exceptions.InvalidSignature:
                    console.print(f"[bold red]Invalid signature![/]")
                    return False
            
            elif key_type == "ec":
                try:
                    public_key.verify(
                        signature,
                        data,
                        ec.ECDSA(hashes.SHA256())
                    )
                    console.print(f"[bold green]Signature verified successfully![/]")
                    return True
                except cryptography.exceptions.InvalidSignature:
                    console.print(f"[bold red]Invalid signature![/]")
                    return False
            
        except Exception as e:
            console.print(f"[bold red]Error verifying signature:[/] {str(e)}")
            return False
    
    def encrypt_with_symmetric_key(self, name, data, output_file=None):
        """Encrypt data using a symmetric key."""
        console.print(f"[bold blue]Encrypting data with symmetric key:[/] {name}")
        
        # Check if key exists
        if name not in self.key_store:
            console.print(f"[bold red]Error:[/] Key with name '{name}' not found.")
            return False
        
        try:
            key_info = self.key_store[name]
            key_type = key_info["type"]
            
            if key_type != "symmetric":
                console.print(f"[bold red]Error:[/] Key '{name}' is not a symmetric key.")
                return False
            
            # Load symmetric key
            key_file = key_info.get("key_file")
            if not key_file or not os.path.exists(key_file):
                console.print(f"[bold red]Error:[/] Symmetric key file not found.")
                return False
            
            with open(key_file, 'rb') as f:
                key_b64 = f.read()
            
            key = base64.b64decode(key_b64)
            
            # Convert data to bytes if it's a string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Generate a random IV
            iv = os.urandom(16)
            
            # Create an encryptor
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Pad the data
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            # Encrypt the data
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and ciphertext
            result = iv + ciphertext
            
            # Encode result in Base64
            result_b64 = base64.b64encode(result).decode('utf-8')
            
            # Save to file if output file is provided
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(result_b64)
                
                console.print(f"[bold green]Encrypted data saved to:[/] {output_file}")
            
            return result_b64
            
        except Exception as e:
            console.print(f"[bold red]Error encrypting data:[/] {str(e)}")
            return False
    
    def decrypt_with_symmetric_key(self, name, ciphertext):
        """Decrypt data using a symmetric key."""
        console.print(f"[bold blue]Decrypting data with symmetric key:[/] {name}")
        
        # Check if key exists
        if name not in self.key_store:
            console.print(f"[bold red]Error:[/] Key with name '{name}' not found.")
            return False
        
        try:
            key_info = self.key_store[name]
            key_type = key_info["type"]
            
            if key_type != "symmetric":
                console.print(f"[bold red]Error:[/] Key '{name}' is not a symmetric key.")
                return False
            
            # Load symmetric key
            key_file = key_info.get("key_file")
            if not key_file or not os.path.exists(key_file):
                console.print(f"[bold red]Error:[/] Symmetric key file not found.")
                return False
            
            with open(key_file, 'rb') as f:
                key_b64 = f.read()
            
            key = base64.b64decode(key_b64)
            
            # Decode Base64 ciphertext if it's a string
            if isinstance(ciphertext, str):
                ciphertext = base64.b64decode(ciphertext)
            
            # Extract IV (first 16 bytes)
            iv = ciphertext[:16]
            actual_ciphertext = ciphertext[16:]
            
            # Create a decryptor
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            # Decrypt the data
            padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
            
            # Unpad the data
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # Try to decode as UTF-8
            try:
                plaintext_str = plaintext.decode('utf-8')
                return plaintext_str
            except:
                return plaintext
            
        except Exception as e:
            console.print(f"[bold red]Error decrypting data:[/] {str(e)}")
            return False
    
    def generate_certificate(self, name, subject_name, valid_days=365, key_type="rsa", key_size=2048, curve="secp256r1", password=None, overwrite=False):
        """Generate a self-signed certificate."""
        console.print(f"[bold blue]Generating self-signed certificate:[/] {name}")
        
        # Check if key already exists
        if name in self.key_store and not overwrite:
            console.print(f"[bold red]Error:[/] Key with name '{name}' already exists. Use overwrite=True to replace it.")
            return False
        
        try:
            # Generate key pair first
            if key_type == "rsa":
                if not self.generate_rsa_key_pair(name, key_size=key_size, password=password, overwrite=overwrite):
                    return False
            elif key_type == "ec":
                if not self.generate_ec_key_pair(name, curve=curve, password=password, overwrite=overwrite):
                    return False
            else:
                console.print(f"[bold red]Error:[/] Unsupported key type: {key_type}")
                return False
            
            # Load private key
            key_info = self.key_store[name]
            private_key_file = key_info["private_key_file"]
            
            with open(private_key_file, 'rb') as f:
                private_key_data = f.read()
            
            if password:
                private_key = load_pem_private_key(private_key_data, password.encode())
            else:
                private_key = load_pem_private_key(private_key_data, None)
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name)
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=valid_days)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            ).sign(private_key, hashes.SHA256())
            
            # Serialize certificate
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            
            # Save certificate to file
            cert_file = self.keys_dir / f"{name}_certificate.pem"
            
            with open(cert_file, 'wb') as f:
                f.write(cert_pem)
            
            # Update key store
            key_info["certificate_file"] = str(cert_file)
            self._save_key_store()
            
            console.print(f"[bold green]Certificate generated successfully![/]")
            console.print(f"[bold green]Certificate saved to:[/] {cert_file}")
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error generating certificate:[/] {str(e)}")
            return False
    
    def _load_key_store(self):
        """Load the key store from file."""
        if os.path.exists(self.key_store_file):
            try:
                with open(self.key_store_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        else:
            return {}
    
    def _save_key_store(self):
        """Save the key store to file."""
        try:
            with open(self.key_store_file, 'w') as f:
                json.dump(self.key_store, f, indent=2)
            return True
        except:
            return False
