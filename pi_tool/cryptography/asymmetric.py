"""
Asymmetric Cryptography module for the Ultimate PI Tool.

This module provides functionality for asymmetric encryption and decryption
using RSA and other public key cryptography algorithms.
"""

import os
import sys
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from rich.console import Console

console = Console()

class AsymmetricCrypto:
    """Asymmetric Cryptography class for encryption, decryption, and key management."""
    
    def __init__(self):
        """Initialize the Asymmetric Cryptography module."""
        pass
    
    def generate_key_pair(self, key_size=2048, private_key_file=None, public_key_file=None):
        """Generate a new RSA key pair."""
        console.print(f"[bold blue]Generating {key_size}-bit RSA key pair[/]")
        
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Save keys to files if specified
            if private_key_file:
                with open(private_key_file, 'wb') as f:
                    f.write(private_pem)
                console.print(f"[bold green]Private key saved to:[/] [bold]{private_key_file}[/]")
            
            if public_key_file:
                with open(public_key_file, 'wb') as f:
                    f.write(public_pem)
                console.print(f"[bold green]Public key saved to:[/] [bold]{public_key_file}[/]")
            
            console.print(f"[bold green]RSA key pair generated successfully![/]")
            
            return private_pem, public_pem
            
        except Exception as e:
            console.print(f"[bold red]Error generating key pair:[/] {str(e)}")
            return None, None
    
    def encrypt_file(self, input_file, output_file, public_key_file):
        """Encrypt a file using RSA public key."""
        console.print(f"[bold blue]Encrypting file:[/] [bold green]{input_file}[/] using RSA")
        
        try:
            # Read input file
            with open(input_file, 'rb') as f:
                plaintext = f.read()
            
            # Read public key
            with open(public_key_file, 'rb') as f:
                public_key_data = f.read()
            
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_data,
                backend=default_backend()
            )
            
            # RSA can only encrypt small amounts of data, so we use hybrid encryption
            # Generate a random symmetric key
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            symmetric_key = os.urandom(32)  # 256-bit key
            iv = os.urandom(16)
            
            # Encrypt the symmetric key with RSA
            encrypted_key = public_key.encrypt(
                symmetric_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Encrypt the data with the symmetric key (AES)
            cipher = Cipher(
                algorithms.AES(symmetric_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Pad the data
            from cryptography.hazmat.primitives import padding
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            
            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine everything: key length (4 bytes) + encrypted key + IV + ciphertext
            key_length = len(encrypted_key).to_bytes(4, byteorder='big')
            result = key_length + encrypted_key + iv + ciphertext
            
            # Write output file
            with open(output_file, 'wb') as f:
                f.write(result)
            
            console.print(f"[bold green]Success![/] File encrypted and saved to: [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def decrypt_file(self, input_file, output_file, private_key_file):
        """Decrypt a file using RSA private key."""
        console.print(f"[bold blue]Decrypting file:[/] [bold green]{input_file}[/] using RSA")
        
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
            
            # Extract key length, encrypted key, IV, and ciphertext
            key_length = int.from_bytes(data[:4], byteorder='big')
            encrypted_key = data[4:4+key_length]
            iv = data[4+key_length:4+key_length+16]
            ciphertext = data[4+key_length+16:]
            
            # Decrypt the symmetric key with RSA
            symmetric_key = private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt the data with the symmetric key (AES)
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            cipher = Cipher(
                algorithms.AES(symmetric_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Unpad the data
            from cryptography.hazmat.primitives import padding
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # Write output file
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            console.print(f"[bold green]Success![/] File decrypted and saved to: [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def encrypt_data(self, data, public_key_data):
        """Encrypt data using RSA public key."""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_data,
                backend=default_backend()
            )
            
            # RSA can only encrypt small amounts of data, so we use hybrid encryption
            # Generate a random symmetric key
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            symmetric_key = os.urandom(32)  # 256-bit key
            iv = os.urandom(16)
            
            # Encrypt the symmetric key with RSA
            encrypted_key = public_key.encrypt(
                symmetric_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Encrypt the data with the symmetric key (AES)
            cipher = Cipher(
                algorithms.AES(symmetric_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Pad the data
            from cryptography.hazmat.primitives import padding
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine everything: key length (4 bytes) + encrypted key + IV + ciphertext
            key_length = len(encrypted_key).to_bytes(4, byteorder='big')
            result = key_length + encrypted_key + iv + ciphertext
            
            return result
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_data(self, data, private_key_data):
        """Decrypt data using RSA private key."""
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )
            
            # Extract key length, encrypted key, IV, and ciphertext
            key_length = int.from_bytes(data[:4], byteorder='big')
            encrypted_key = data[4:4+key_length]
            iv = data[4+key_length:4+key_length+16]
            ciphertext = data[4+key_length+16:]
            
            # Decrypt the symmetric key with RSA
            symmetric_key = private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt the data with the symmetric key (AES)
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            cipher = Cipher(
                algorithms.AES(symmetric_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Unpad the data
            from cryptography.hazmat.primitives import padding
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
