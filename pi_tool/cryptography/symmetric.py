"""
Symmetric Cryptography module for the Ultimate PI Tool.

This module provides functionality for symmetric encryption and decryption
using various algorithms including AES, ChaCha20, and more.
"""

import os
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from rich.console import Console

console = Console()

class SymmetricCrypto:
    """Symmetric Cryptography class for encryption and decryption."""
    
    def __init__(self):
        """Initialize the Symmetric Cryptography module."""
        self.supported_algorithms = {
            'aes': self._aes_encrypt_decrypt,
            'chacha20': self._chacha20_encrypt_decrypt,
            'fernet': self._fernet_encrypt_decrypt
        }
    
    def encrypt_file(self, input_file, output_file, password, algorithm='aes'):
        """Encrypt a file using the specified symmetric algorithm."""
        console.print(f"[bold blue]Encrypting file:[/] [bold green]{input_file}[/] using {algorithm.upper()}")
        
        try:
            # Read input file
            with open(input_file, 'rb') as f:
                plaintext = f.read()
            
            # Encrypt data
            if algorithm.lower() in self.supported_algorithms:
                ciphertext = self.encrypt_data(plaintext, password, algorithm.lower())
            else:
                console.print(f"[bold red]Error:[/] Unsupported algorithm: {algorithm}")
                console.print(f"[bold blue]Supported algorithms:[/] {', '.join(self.supported_algorithms.keys())}")
                return False
            
            # Write output file
            with open(output_file, 'wb') as f:
                f.write(ciphertext)
            
            console.print(f"[bold green]Success![/] File encrypted and saved to: [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def decrypt_file(self, input_file, output_file, password, algorithm='aes'):
        """Decrypt a file using the specified symmetric algorithm."""
        console.print(f"[bold blue]Decrypting file:[/] [bold green]{input_file}[/] using {algorithm.upper()}")
        
        try:
            # Read input file
            with open(input_file, 'rb') as f:
                ciphertext = f.read()
            
            # Decrypt data
            if algorithm.lower() in self.supported_algorithms:
                plaintext = self.decrypt_data(ciphertext, password, algorithm.lower())
            else:
                console.print(f"[bold red]Error:[/] Unsupported algorithm: {algorithm}")
                console.print(f"[bold blue]Supported algorithms:[/] {', '.join(self.supported_algorithms.keys())}")
                return False
            
            # Write output file
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            console.print(f"[bold green]Success![/] File decrypted and saved to: [bold]{output_file}[/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def encrypt_data(self, data, password, algorithm='aes'):
        """Encrypt data using the specified symmetric algorithm."""
        if algorithm.lower() in self.supported_algorithms:
            return self.supported_algorithms[algorithm.lower()](data, password, encrypt=True)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def decrypt_data(self, data, password, algorithm='aes'):
        """Decrypt data using the specified symmetric algorithm."""
        if algorithm.lower() in self.supported_algorithms:
            return self.supported_algorithms[algorithm.lower()](data, password, encrypt=False)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def _derive_key(self, password, salt=None, key_size=32):
        """Derive a key from a password using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode() if isinstance(password, str) else password)
        return key, salt
    
    def _aes_encrypt_decrypt(self, data, password, encrypt=True):
        """Encrypt or decrypt data using AES-256-CBC."""
        try:
            if encrypt:
                # Generate salt and derive key
                salt = os.urandom(16)
                key, _ = self._derive_key(password, salt)
                
                # Generate IV
                iv = os.urandom(16)
                
                # Create cipher
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                
                # Pad data
                padder = padding.PKCS7(algorithms.AES.block_size).padder()
                padded_data = padder.update(data) + padder.finalize()
                
                # Encrypt data
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                
                # Combine salt, IV, and ciphertext
                result = salt + iv + ciphertext
                
                return result
            else:
                # Extract salt and IV
                salt = data[:16]
                iv = data[16:32]
                ciphertext = data[32:]
                
                # Derive key
                key, _ = self._derive_key(password, salt)
                
                # Create cipher
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                
                # Decrypt data
                decryptor = cipher.decryptor()
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Unpad data
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                
                return plaintext
                
        except Exception as e:
            if encrypt:
                raise Exception(f"Encryption failed: {str(e)}")
            else:
                raise Exception(f"Decryption failed: {str(e)}")
    
    def _chacha20_encrypt_decrypt(self, data, password, encrypt=True):
        """Encrypt or decrypt data using ChaCha20."""
        try:
            if encrypt:
                # Generate salt and derive key
                salt = os.urandom(16)
                key, _ = self._derive_key(password, salt, key_size=32)
                
                # Generate nonce
                nonce = os.urandom(16)
                
                # Create cipher
                algorithm = algorithms.ChaCha20(key, nonce)
                cipher = Cipher(algorithm, mode=None, backend=default_backend())
                
                # Encrypt data
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(data) + encryptor.finalize()
                
                # Combine salt, nonce, and ciphertext
                result = salt + nonce + ciphertext
                
                return result
            else:
                # Extract salt and nonce
                salt = data[:16]
                nonce = data[16:32]
                ciphertext = data[32:]
                
                # Derive key
                key, _ = self._derive_key(password, salt, key_size=32)
                
                # Create cipher
                algorithm = algorithms.ChaCha20(key, nonce)
                cipher = Cipher(algorithm, mode=None, backend=default_backend())
                
                # Decrypt data
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                return plaintext
                
        except Exception as e:
            if encrypt:
                raise Exception(f"Encryption failed: {str(e)}")
            else:
                raise Exception(f"Decryption failed: {str(e)}")
    
    def _fernet_encrypt_decrypt(self, data, password, encrypt=True):
        """Encrypt or decrypt data using Fernet (AES-128-CBC with HMAC)."""
        try:
            from cryptography.fernet import Fernet
            
            if encrypt:
                # Generate salt and derive key
                salt = os.urandom(16)
                key, _ = self._derive_key(password, salt, key_size=32)
                
                # Convert key to Fernet key (base64-encoded)
                fernet_key = base64.urlsafe_b64encode(key)
                
                # Create Fernet cipher
                cipher = Fernet(fernet_key)
                
                # Encrypt data
                ciphertext = cipher.encrypt(data)
                
                # Combine salt and ciphertext
                result = salt + ciphertext
                
                return result
            else:
                # Extract salt
                salt = data[:16]
                ciphertext = data[16:]
                
                # Derive key
                key, _ = self._derive_key(password, salt, key_size=32)
                
                # Convert key to Fernet key (base64-encoded)
                fernet_key = base64.urlsafe_b64encode(key)
                
                # Create Fernet cipher
                cipher = Fernet(fernet_key)
                
                # Decrypt data
                plaintext = cipher.decrypt(ciphertext)
                
                return plaintext
                
        except Exception as e:
            if encrypt:
                raise Exception(f"Encryption failed: {str(e)}")
            else:
                raise Exception(f"Decryption failed: {str(e)}")
    
    def list_algorithms(self):
        """List supported encryption algorithms."""
        console.print("[bold blue]Supported Symmetric Encryption Algorithms:[/]")
        for algorithm in self.supported_algorithms.keys():
            console.print(f"- {algorithm.upper()}")
        return list(self.supported_algorithms.keys())
