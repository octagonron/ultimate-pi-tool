"""
Decoders module for the Ultimate PI Tool.

This module provides functionality for decoding various encoding schemes
including base64, hex, URL, HTML, and more.
"""

import os
import sys
import json
import base64
import binascii
import urllib.parse
import html
import re
import quopri
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax

console = Console()

class Decoders:
    """Decoders class for decoding various encoding schemes."""
    
    def __init__(self):
        """Initialize the Decoders module."""
        # Define supported encoding schemes
        self.supported_schemes = [
            "base64", "hex", "url", "html", "quoted_printable", 
            "rot13", "ascii", "binary", "morse", "unicode"
        ]
    
    def detect_encoding(self, data):
        """Attempt to detect the encoding scheme of the provided data."""
        console.print(f"[bold blue]Detecting encoding scheme for input data[/]")
        
        if not data:
            console.print("[bold red]Error:[/] Input data is empty")
            return None
        
        # Check if data is a string
        if not isinstance(data, str):
            try:
                data = str(data)
            except:
                console.print("[bold red]Error:[/] Input data must be a string or convertible to string")
                return None
        
        # Create results table
        table = Table(title="Encoding Detection Results")
        table.add_column("Encoding", style="cyan")
        table.add_column("Confidence", style="green")
        table.add_column("Sample Decoded", style="yellow")
        
        results = []
        
        # Check for Base64
        if self._is_base64(data):
            try:
                decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
                sample = decoded[:50] + "..." if len(decoded) > 50 else decoded
                confidence = "High" if self._is_readable_text(decoded) else "Medium"
                results.append(("base64", confidence, sample))
                table.add_row("Base64", confidence, sample)
            except:
                pass
        
        # Check for Hex
        if self._is_hex(data):
            try:
                decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
                sample = decoded[:50] + "..." if len(decoded) > 50 else decoded
                confidence = "High" if self._is_readable_text(decoded) else "Medium"
                results.append(("hex", confidence, sample))
                table.add_row("Hex", confidence, sample)
            except:
                pass
        
        # Check for URL encoding
        if '%' in data:
            try:
                decoded = urllib.parse.unquote(data)
                if decoded != data:
                    sample = decoded[:50] + "..." if len(decoded) > 50 else decoded
                    confidence = "High"
                    results.append(("url", confidence, sample))
                    table.add_row("URL", confidence, sample)
            except:
                pass
        
        # Check for HTML encoding
        if '&' in data and ';' in data:
            try:
                decoded = html.unescape(data)
                if decoded != data:
                    sample = decoded[:50] + "..." if len(decoded) > 50 else decoded
                    confidence = "High"
                    results.append(("html", confidence, sample))
                    table.add_row("HTML", confidence, sample)
            except:
                pass
        
        # Check for Quoted-Printable
        if '=' in data and re.search(r'=[0-9A-F]{2}', data):
            try:
                decoded = quopri.decodestring(data).decode('utf-8', errors='ignore')
                if decoded != data:
                    sample = decoded[:50] + "..." if len(decoded) > 50 else decoded
                    confidence = "Medium"
                    results.append(("quoted_printable", confidence, sample))
                    table.add_row("Quoted-Printable", confidence, sample)
            except:
                pass
        
        # Check for ROT13
        if self._is_alpha(data):
            decoded = self._rot13(data)
            if self._is_readable_text(decoded):
                sample = decoded[:50] + "..." if len(decoded) > 50 else decoded
                confidence = "Medium"
                results.append(("rot13", confidence, sample))
                table.add_row("ROT13", confidence, sample)
        
        # Check for Binary
        if self._is_binary(data):
            try:
                # Convert binary to ASCII
                binary_values = data.split()
                decoded = ''.join([chr(int(binary, 2)) for binary in binary_values])
                if self._is_readable_text(decoded):
                    sample = decoded[:50] + "..." if len(decoded) > 50 else decoded
                    confidence = "High"
                    results.append(("binary", confidence, sample))
                    table.add_row("Binary", confidence, sample)
            except:
                pass
        
        # Check for Morse code
        if self._is_morse(data):
            decoded = self._decode_morse(data)
            if decoded:
                sample = decoded[:50] + "..." if len(decoded) > 50 else decoded
                confidence = "High"
                results.append(("morse", confidence, sample))
                table.add_row("Morse Code", confidence, sample)
        
        # Check for Unicode escapes
        if '\\u' in data:
            try:
                # Handle Python-style unicode escapes
                decoded = data.encode('utf-8').decode('unicode_escape')
                if decoded != data:
                    sample = decoded[:50] + "..." if len(decoded) > 50 else decoded
                    confidence = "High"
                    results.append(("unicode", confidence, sample))
                    table.add_row("Unicode", confidence, sample)
            except:
                pass
        
        # Display results
        if results:
            console.print(table)
            # Return the encoding with highest confidence
            return sorted(results, key=lambda x: 0 if x[1] == "High" else 1 if x[1] == "Medium" else 2)[0][0]
        else:
            console.print("[bold yellow]Warning:[/] Could not detect encoding scheme")
            return None
    
    def decode(self, data, scheme=None):
        """Decode data using the specified encoding scheme."""
        if not data:
            console.print("[bold red]Error:[/] Input data is empty")
            return None
        
        # Auto-detect scheme if not provided
        if not scheme:
            scheme = self.detect_encoding(data)
            if not scheme:
                console.print("[bold yellow]Warning:[/] Could not auto-detect encoding scheme, trying all decoders")
                return self.decode_all(data)
        
        console.print(f"[bold blue]Decoding data using {scheme} scheme[/]")
        
        # Decode based on scheme
        if scheme.lower() == "base64":
            return self.decode_base64(data)
        elif scheme.lower() == "hex":
            return self.decode_hex(data)
        elif scheme.lower() == "url":
            return self.decode_url(data)
        elif scheme.lower() == "html":
            return self.decode_html(data)
        elif scheme.lower() == "quoted_printable":
            return self.decode_quoted_printable(data)
        elif scheme.lower() == "rot13":
            return self.decode_rot13(data)
        elif scheme.lower() == "ascii":
            return self.decode_ascii(data)
        elif scheme.lower() == "binary":
            return self.decode_binary(data)
        elif scheme.lower() == "morse":
            return self.decode_morse(data)
        elif scheme.lower() == "unicode":
            return self.decode_unicode(data)
        else:
            console.print(f"[bold red]Error:[/] Unsupported encoding scheme: {scheme}")
            console.print(f"[bold yellow]Supported schemes:[/] {', '.join(self.supported_schemes)}")
            return None
    
    def decode_all(self, data):
        """Try all decoders and return all successful results."""
        console.print(f"[bold blue]Trying all decoders on input data[/]")
        
        if not data:
            console.print("[bold red]Error:[/] Input data is empty")
            return None
        
        # Create results table
        table = Table(title="Decoding Results")
        table.add_column("Encoding", style="cyan")
        table.add_column("Decoded Result", style="green")
        
        results = {}
        
        # Try all decoders
        for scheme in self.supported_schemes:
            try:
                result = None
                if scheme == "base64":
                    result = self.decode_base64(data, silent=True)
                elif scheme == "hex":
                    result = self.decode_hex(data, silent=True)
                elif scheme == "url":
                    result = self.decode_url(data, silent=True)
                elif scheme == "html":
                    result = self.decode_html(data, silent=True)
                elif scheme == "quoted_printable":
                    result = self.decode_quoted_printable(data, silent=True)
                elif scheme == "rot13":
                    result = self.decode_rot13(data, silent=True)
                elif scheme == "ascii":
                    result = self.decode_ascii(data, silent=True)
                elif scheme == "binary":
                    result = self.decode_binary(data, silent=True)
                elif scheme == "morse":
                    result = self.decode_morse(data, silent=True)
                elif scheme == "unicode":
                    result = self.decode_unicode(data, silent=True)
                
                if result and result != data:
                    results[scheme] = result
                    sample = result[:50] + "..." if len(result) > 50 else result
                    table.add_row(scheme.capitalize(), sample)
            except:
                pass
        
        # Display results
        if results:
            console.print(table)
            return results
        else:
            console.print("[bold yellow]Warning:[/] Could not decode data with any scheme")
            return None
    
    def decode_base64(self, data, silent=False):
        """Decode Base64 encoded data."""
        if not silent:
            console.print(f"[bold blue]Decoding Base64 data[/]")
        
        try:
            # Handle padding if missing
            padding_needed = len(data) % 4
            if padding_needed:
                data += '=' * (4 - padding_needed)
            
            # Decode
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            
            if not silent:
                self._display_decoded_result("Base64", data, decoded)
            
            return decoded
        except Exception as e:
            if not silent:
                console.print(f"[bold red]Error decoding Base64:[/] {str(e)}")
            return None
    
    def decode_hex(self, data, silent=False):
        """Decode hexadecimal encoded data."""
        if not silent:
            console.print(f"[bold blue]Decoding Hex data[/]")
        
        try:
            # Remove any spaces or non-hex characters
            data = ''.join([c for c in data if c in '0123456789abcdefABCDEF'])
            
            # Ensure even length
            if len(data) % 2 != 0:
                data = '0' + data
            
            # Decode
            decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
            
            if not silent:
                self._display_decoded_result("Hex", data, decoded)
            
            return decoded
        except Exception as e:
            if not silent:
                console.print(f"[bold red]Error decoding Hex:[/] {str(e)}")
            return None
    
    def decode_url(self, data, silent=False):
        """Decode URL encoded data."""
        if not silent:
            console.print(f"[bold blue]Decoding URL encoded data[/]")
        
        try:
            # Decode
            decoded = urllib.parse.unquote(data)
            
            if not silent:
                self._display_decoded_result("URL", data, decoded)
            
            return decoded
        except Exception as e:
            if not silent:
                console.print(f"[bold red]Error decoding URL:[/] {str(e)}")
            return None
    
    def decode_html(self, data, silent=False):
        """Decode HTML encoded data."""
        if not silent:
            console.print(f"[bold blue]Decoding HTML encoded data[/]")
        
        try:
            # Decode
            decoded = html.unescape(data)
            
            if not silent:
                self._display_decoded_result("HTML", data, decoded)
            
            return decoded
        except Exception as e:
            if not silent:
                console.print(f"[bold red]Error decoding HTML:[/] {str(e)}")
            return None
    
    def decode_quoted_printable(self, data, silent=False):
        """Decode Quoted-Printable encoded data."""
        if not silent:
            console.print(f"[bold blue]Decoding Quoted-Printable data[/]")
        
        try:
            # Decode
            decoded = quopri.decodestring(data).decode('utf-8', errors='ignore')
            
            if not silent:
                self._display_decoded_result("Quoted-Printable", data, decoded)
            
            return decoded
        except Exception as e:
            if not silent:
                console.print(f"[bold red]Error decoding Quoted-Printable:[/] {str(e)}")
            return None
    
    def decode_rot13(self, data, silent=False):
        """Decode ROT13 encoded data."""
        if not silent:
            console.print(f"[bold blue]Decoding ROT13 data[/]")
        
        try:
            # Decode
            decoded = self._rot13(data)
            
            if not silent:
                self._display_decoded_result("ROT13", data, decoded)
            
            return decoded
        except Exception as e:
            if not silent:
                console.print(f"[bold red]Error decoding ROT13:[/] {str(e)}")
            return None
    
    def decode_ascii(self, data, silent=False):
        """Decode ASCII values to text."""
        if not silent:
            console.print(f"[bold blue]Decoding ASCII values[/]")
        
        try:
            # Split by spaces, commas, or other common separators
            values = re.split(r'[,\s]+', data)
            
            # Convert to characters
            decoded = ''.join([chr(int(val)) for val in values if val.isdigit() and 0 <= int(val) <= 127])
            
            if not silent:
                self._display_decoded_result("ASCII", data, decoded)
            
            return decoded
        except Exception as e:
            if not silent:
                console.print(f"[bold red]Error decoding ASCII:[/] {str(e)}")
            return None
    
    def decode_binary(self, data, silent=False):
        """Decode binary data to text."""
        if not silent:
            console.print(f"[bold blue]Decoding Binary data[/]")
        
        try:
            # Split by spaces
            binary_values = data.split()
            
            # Convert to characters
            decoded = ''.join([chr(int(binary, 2)) for binary in binary_values])
            
            if not silent:
                self._display_decoded_result("Binary", data, decoded)
            
            return decoded
        except Exception as e:
            if not silent:
                console.print(f"[bold red]Error decoding Binary:[/] {str(e)}")
            return None
    
    def decode_morse(self, data, silent=False):
        """Decode Morse code to text."""
        if not silent:
            console.print(f"[bold blue]Decoding Morse code[/]")
        
        try:
            # Decode
            decoded = self._decode_morse(data)
            
            if not silent:
                self._display_decoded_result("Morse", data, decoded)
            
            return decoded
        except Exception as e:
            if not silent:
                console.print(f"[bold red]Error decoding Morse:[/] {str(e)}")
            return None
    
    def decode_unicode(self, data, silent=False):
        """Decode Unicode escape sequences."""
        if not silent:
            console.print(f"[bold blue]Decoding Unicode escape sequences[/]")
        
        try:
            # Decode
            decoded = data.encode('utf-8').decode('unicode_escape')
            
            if not silent:
                self._display_decoded_result("Unicode", data, decoded)
            
            return decoded
        except Exception as e:
            if not silent:
                console.print(f"[bold red]Error decoding Unicode:[/] {str(e)}")
            return None
    
    def decode_file(self, file_path, scheme=None):
        """Decode data from a file using the specified encoding scheme."""
        console.print(f"[bold blue]Decoding file:[/] {file_path}")
        
        try:
            # Read file
            with open(file_path, 'r') as f:
                data = f.read()
            
            # Decode
            return self.decode(data, scheme)
            
        except Exception as e:
            console.print(f"[bold red]Error reading file:[/] {str(e)}")
            return None
    
    def save_to_file(self, decoded_data, output_file):
        """Save decoded data to a file."""
        console.print(f"[bold blue]Saving decoded data to:[/] [bold green]{output_file}[/]")
        
        try:
            with open(output_file, 'w') as f:
                f.write(decoded_data)
            
            console.print(f"[bold green]Decoded data saved successfully![/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error saving decoded data:[/] {str(e)}")
            return False
    
    def _is_base64(self, data):
        """Check if data is likely Base64 encoded."""
        # Remove any whitespace
        data = data.strip()
        
        # Check if length is a multiple of 4 (with padding)
        if len(data) % 4 != 0 and not data.endswith('='):
            return False
        
        # Check if characters are valid Base64
        return bool(re.match(r'^[A-Za-z0-9+/=]+$', data))
    
    def _is_hex(self, data):
        """Check if data is likely hex encoded."""
        # Remove any whitespace
        data = data.strip()
        
        # Check if characters are valid hex
        return bool(re.match(r'^[0-9A-Fa-f]+$', data))
    
    def _is_alpha(self, data):
        """Check if data contains mostly alphabetic characters."""
        # Count alphabetic characters
        alpha_count = sum(1 for c in data if c.isalpha())
        
        # Check if at least 70% of characters are alphabetic
        return alpha_count / len(data) >= 0.7 if data else False
    
    def _is_binary(self, data):
        """Check if data is likely binary encoded."""
        # Check if data consists of 0s and 1s with possible spaces
        return bool(re.match(r'^[01\s]+$', data))
    
    def _is_morse(self, data):
        """Check if data is likely Morse code."""
        # Check if data consists of dots, dashes, and spaces
        return bool(re.match(r'^[\.\-\s/]+$', data))
    
    def _is_readable_text(self, text):
        """Check if text is likely readable (contains mostly printable ASCII)."""
        # Count printable ASCII characters
        printable_count = sum(1 for c in text if 32 <= ord(c) <= 126)
        
        # Check if at least 80% of characters are printable ASCII
        return printable_count / len(text) >= 0.8 if text else False
    
    def _rot13(self, text):
        """Apply ROT13 transformation to text."""
        result = ""
        for char in text:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result
    
    def _decode_morse(self, morse_code):
        """Decode Morse code to text."""
        # Morse code dictionary
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
            '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
            '-----': '0', '--..--': ',', '.-.-.-': '.', '..--..': '?',
            '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&',
            '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+',
            '-....-': '-', '..--.-': '_', '.-..-.': '"', '...-..-': '$',
            '.--.-.': '@', '-.-.--': '!'
        }
        
        # Split by word and character separators
        words = morse_code.strip().split('/')
        result = []
        
        for word in words:
            chars = word.strip().split()
            word_result = []
            
            for char in chars:
                if char in morse_dict:
                    word_result.append(morse_dict[char])
                else:
                    # Skip invalid characters
                    pass
            
            result.append(''.join(word_result))
        
        return ' '.join(result)
    
    def _display_decoded_result(self, scheme, original, decoded):
        """Display the decoded result in a formatted way."""
        # Create table
        table = Table(title=f"{scheme} Decoding Result")
        table.add_column("Original", style="cyan")
        table.add_column("Decoded", style="green")
        
        # Truncate long strings for display
        original_display = original[:100] + "..." if len(original) > 100 else original
        decoded_display = decoded[:100] + "..." if len(decoded) > 100 else decoded
        
        table.add_row(original_display, decoded_display)
        console.print(table)
        
        # Display syntax highlighted if it looks like code
        if any(marker in decoded for marker in ['<html', '<?xml', '<?php', 'function', 'class', 'def ', 'import ', 'package ']):
            # Try to detect language
            language = "html" if '<html' in decoded else "xml" if '<?xml' in decoded else "php" if '<?php' in decoded else "javascript" if 'function' in decoded or 'class' in decoded else "python" if 'def ' in decoded or 'import ' in decoded else "java" if 'package ' in decoded else "text"
            
            syntax = Syntax(decoded, language, theme="monokai", line_numbers=True)
            console.print("Syntax Highlighted Result:")
            console.print(syntax)


class BinaryDecoders:
    """Binary Decoders class for decoding various binary file formats."""
    
    def __init__(self):
        """Initialize the Binary Decoders module."""
        # Define supported file types
        self.supported_types = [
            "image", "audio", "video", "document", "archive"
        ]
    
    def detect_file_type(self, file_path):
        """Detect the type of a binary file based on its magic numbers."""
        console.print(f"[bold blue]Detecting file type for:[/] {file_path}")
        
        try:
            # Read first 16 bytes
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            # Check magic numbers
            if header.startswith(b'\xFF\xD8\xFF'):
                return "image/jpeg"
            elif header.startswith(b'\x89PNG\r\n\x1A\n'):
                return "image/png"
            elif header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
                return "image/gif"
            elif header.startswith(b'BM'):
                return "image/bmp"
            elif header.startswith(b'\x49\x49\x2A\x00') or header.startswith(b'\x4D\x4D\x00\x2A'):
                return "image/tiff"
            elif header.startswith(b'RIFF') and header[8:12] == b'WAVE':
                return "audio/wav"
            elif header.startswith(b'ID3') or header.startswith(b'\xFF\xFB') or header.startswith(b'\xFF\xF3') or header.startswith(b'\xFF\xF2'):
                return "audio/mp3"
            elif header.startswith(b'\x00\x00\x00\x14ftyp'):
                if header[8:12] in (b'qt  ', b'moov'):
                    return "video/quicktime"
                else:
                    return "video/mp4"
            elif header.startswith(b'\x1A\x45\xDF\xA3'):
                return "video/webm"
            elif header.startswith(b'%PDF'):
                return "application/pdf"
            elif header.startswith(b'PK\x03\x04'):
                return "application/zip"
            elif header.startswith(b'Rar!\x1A\x07'):
                return "application/x-rar-compressed"
            elif header.startswith(b'\x1F\x8B'):
                return "application/gzip"
            elif header.startswith(b'7z\xBC\xAF\x27\x1C'):
                return "application/x-7z-compressed"
            elif header.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
                return "application/msword"
            elif header.startswith(b'PK\x03\x04') and b'[Content_Types].xml' in open(file_path, 'rb').read(1000):
                return "application/vnd.openxmlformats-officedocument"
            else:
                # Try to detect text files
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read(1000)
                    
                    if '<?xml' in content:
                        return "text/xml"
                    elif '<html' in content:
                        return "text/html"
                    elif '<?php' in content:
                        return "text/php"
                    elif 'import ' in content or 'def ' in content:
                        return "text/python"
                    elif 'function ' in content or 'class ' in content:
                        return "text/javascript"
                    else:
                        return "text/plain"
                except:
                    return "application/octet-stream"
        
        except Exception as e:
            console.print(f"[bold red]Error detecting file type:[/] {str(e)}")
            return None
    
    def extract_metadata(self, file_path):
        """Extract metadata from a binary file."""
        console.print(f"[bold blue]Extracting metadata from:[/] {file_path}")
        
        # Detect file type
        file_type = self.detect_file_type(file_path)
        
        if not file_type:
            console.print("[bold red]Error:[/] Could not detect file type")
            return None
        
        console.print(f"[bold green]Detected file type:[/] {file_type}")
        
        # Extract metadata based on file type
        metadata = {
            "file_path": file_path,
            "file_type": file_type,
            "file_size": os.path.getsize(file_path),
            "created": datetime.datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
            "modified": datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # TODO: Add specific metadata extraction for different file types
        # This would require additional libraries like PIL for images, mutagen for audio, etc.
        
        # Display metadata
        table = Table(title="File Metadata")
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in metadata.items():
            table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(table)
        
        return metadata
    
    def extract_embedded_data(self, file_path):
        """Extract potentially embedded data from a binary file."""
        console.print(f"[bold blue]Searching for embedded data in:[/] {file_path}")
        
        # Detect file type
        file_type = self.detect_file_type(file_path)
        
        if not file_type:
            console.print("[bold red]Error:[/] Could not detect file type")
            return None
        
        # Read file
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            console.print(f"[bold red]Error reading file:[/] {str(e)}")
            return None
        
        # Search for common embedded data patterns
        findings = []
        
        # Look for URLs
        url_pattern = re.compile(b'https?://[^\s<>"]+|www\.[^\s<>"]+')
        urls = url_pattern.findall(data)
        
        if urls:
            findings.append({
                "type": "URLs",
                "count": len(urls),
                "data": [url.decode('utf-8', errors='ignore') for url in urls]
            })
        
        # Look for email addresses
        email_pattern = re.compile(b'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        emails = email_pattern.findall(data)
        
        if emails:
            findings.append({
                "type": "Email Addresses",
                "count": len(emails),
                "data": [email.decode('utf-8', errors='ignore') for email in emails]
            })
        
        # Look for IP addresses
        ip_pattern = re.compile(b'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        ips = ip_pattern.findall(data)
        
        if ips:
            findings.append({
                "type": "IP Addresses",
                "count": len(ips),
                "data": [ip.decode('utf-8', errors='ignore') for ip in ips]
            })
        
        # Look for Base64 encoded data
        base64_pattern = re.compile(b'[A-Za-z0-9+/]{30,}={0,2}')
        base64_data = base64_pattern.findall(data)
        
        if base64_data:
            findings.append({
                "type": "Base64 Data",
                "count": len(base64_data),
                "data": [b64.decode('utf-8', errors='ignore') for b64 in base64_data[:5]]  # Limit to first 5
            })
        
        # Look for embedded file signatures
        file_signatures = {
            b'\xFF\xD8\xFF': "JPEG image",
            b'\x89PNG\r\n\x1A\n': "PNG image",
            b'GIF87a': "GIF image",
            b'GIF89a': "GIF image",
            b'BM': "BMP image",
            b'%PDF': "PDF document",
            b'PK\x03\x04': "ZIP archive",
            b'Rar!\x1A\x07': "RAR archive",
            b'\x1F\x8B': "GZIP archive",
            b'7z\xBC\xAF\x27\x1C': "7-Zip archive"
        }
        
        for signature, file_type in file_signatures.items():
            # Skip if this is the main file type
            if file_type.lower() in self.detect_file_type(file_path).lower():
                continue
            
            # Find all occurrences of the signature
            positions = []
            pos = -1
            while True:
                pos = data.find(signature, pos + 1)
                if pos == -1:
                    break
                positions.append(pos)
            
            if positions:
                findings.append({
                    "type": f"Embedded {file_type}",
                    "count": len(positions),
                    "data": [f"Found at offset: {pos}" for pos in positions]
                })
        
        # Display findings
        if findings:
            for finding in findings:
                table = Table(title=f"Found {finding['count']} {finding['type']}")
                table.add_column("Data", style="green")
                
                for item in finding['data']:
                    table.add_row(item)
                
                console.print(table)
            
            return findings
        else:
            console.print("[bold yellow]No embedded data found[/]")
            return None
    
    def convert_file(self, input_file, output_format, output_file=None):
        """Convert a binary file to a different format."""
        console.print(f"[bold blue]Converting file to {output_format}:[/] {input_file}")
        
        # Detect input file type
        input_type = self.detect_file_type(input_file)
        
        if not input_type:
            console.print("[bold red]Error:[/] Could not detect input file type")
            return None
        
        # Determine output file if not provided
        if not output_file:
            base_name = os.path.splitext(input_file)[0]
            output_file = f"{base_name}.{output_format.lower()}"
        
        console.print(f"[bold yellow]File conversion requires external libraries and is not implemented in this version[/]")
        console.print(f"[bold yellow]Would convert {input_type} to {output_format} and save as {output_file}[/]")
        
        return None
