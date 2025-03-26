"""
Text Steganography module for the Ultimate PI Tool.

This module provides functionality for hiding and extracting data in text
using various steganography techniques including whitespace, Unicode, and linguistic methods.
"""

import os
import sys
import re
from rich.console import Console

console = Console()

class TextSteganography:
    """Text Steganography class for hiding and extracting data in text."""
    
    def __init__(self):
        """Initialize the Text Steganography module."""
        pass
    
    def hide_data(self, text_path, data, output_path=None, method="whitespace"):
        """Hide data in a text file using the specified method."""
        console.print(f"[bold blue]Hiding data in text:[/] [bold green]{text_path}[/]")
        
        # Determine output path if not specified
        if not output_path:
            filename, ext = os.path.splitext(text_path)
            output_path = f"{filename}_stego{ext}"
        
        # Read the text file
        try:
            with open(text_path, 'r', encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            console.print(f"[bold red]Error:[/] Failed to read text file: {str(e)}")
            return False
        
        # Convert data to binary if it's a string
        if isinstance(data, str):
            # If data is a file path, read the file
            if os.path.isfile(data):
                try:
                    with open(data, 'rb') as f:
                        binary_data = f.read()
                except Exception as e:
                    console.print(f"[bold red]Error:[/] Failed to read data file: {str(e)}")
                    return False
            else:
                # Otherwise, treat as text
                binary_data = data.encode('utf-8')
        else:
            binary_data = data
        
        # Choose the appropriate method
        if method.lower() == "whitespace":
            result_text = self._hide_whitespace(text, binary_data)
        elif method.lower() == "unicode":
            result_text = self._hide_unicode(text, binary_data)
        elif method.lower() == "zero-width":
            result_text = self._hide_zero_width(text, binary_data)
        else:
            console.print(f"[bold red]Error:[/] Unsupported method: {method}")
            return False
        
        if result_text:
            # Save the result to the output file
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(result_text)
                console.print(f"[bold green]Success![/] Data hidden in text: [bold]{output_path}[/]")
                return True
            except Exception as e:
                console.print(f"[bold red]Error:[/] Failed to write output file: {str(e)}")
                return False
        else:
            console.print(f"[bold red]Error:[/] Failed to hide data in text")
            return False
    
    def extract_data(self, text_path, output_file=None, method="whitespace"):
        """Extract hidden data from a text file using the specified method."""
        console.print(f"[bold blue]Extracting data from text:[/] [bold green]{text_path}[/]")
        
        # Read the text file
        try:
            with open(text_path, 'r', encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            console.print(f"[bold red]Error:[/] Failed to read text file: {str(e)}")
            return False
        
        # Choose the appropriate method
        if method.lower() == "whitespace":
            data = self._extract_whitespace(text)
        elif method.lower() == "unicode":
            data = self._extract_unicode(text)
        elif method.lower() == "zero-width":
            data = self._extract_zero_width(text)
        else:
            console.print(f"[bold red]Error:[/] Unsupported method: {method}")
            return False
        
        if data:
            # If output file is specified, save the data to the file
            if output_file:
                try:
                    with open(output_file, 'wb') as f:
                        f.write(data)
                    console.print(f"[bold green]Success![/] Extracted data saved to: [bold]{output_file}[/]")
                except Exception as e:
                    console.print(f"[bold red]Error:[/] Failed to save extracted data: {str(e)}")
                    return False
            else:
                # Try to decode as text and display
                try:
                    text_data = data.decode('utf-8')
                    console.print(f"[bold green]Extracted data:[/] {text_data}")
                except UnicodeDecodeError:
                    console.print(f"[bold yellow]Warning:[/] Extracted data is not valid UTF-8 text")
                    console.print(f"[bold green]Extracted data (hex):[/] {data.hex()[:100]}...")
            
            return True
        else:
            console.print(f"[bold red]Error:[/] Failed to extract data from text")
            return False
    
    def _hide_whitespace(self, text, data):
        """Hide data in text using whitespace steganography."""
        try:
            # Convert data to binary string
            binary_string = ''.join(format(byte, '08b') for byte in data)
            
            # Add length information to the beginning
            length = len(data)
            length_binary = format(length, '032b')  # 32 bits for length (4 bytes)
            binary_string = length_binary + binary_string
            
            # Split text into lines
            lines = text.split('\n')
            
            # Check if we have enough lines to hide the data
            if len(lines) < len(binary_string):
                console.print(f"[bold red]Error:[/] Text too small to hide {len(data)} bytes of data")
                return None
            
            # Hide data by adding spaces at the end of each line
            for i in range(len(binary_string)):
                if i < len(lines):
                    if binary_string[i] == '1':
                        # Add two spaces for '1'
                        lines[i] = lines[i].rstrip() + '  '
                    else:
                        # Add one space for '0'
                        lines[i] = lines[i].rstrip() + ' '
            
            # Join lines back into text
            result_text = '\n'.join(lines)
            
            console.print(f"[bold green]Data hidden successfully:[/] {len(data)} bytes hidden in text using whitespace method")
            return result_text
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def _extract_whitespace(self, text):
        """Extract hidden data from text using whitespace steganography."""
        try:
            # Split text into lines
            lines = text.split('\n')
            
            # Extract binary string from trailing spaces
            binary_string = ''
            for line in lines:
                trailing_spaces = len(line) - len(line.rstrip())
                if trailing_spaces == 2:
                    binary_string += '1'
                elif trailing_spaces == 1:
                    binary_string += '0'
                else:
                    # No trailing spaces, stop extraction
                    break
            
            # Check if we have enough bits for length information
            if len(binary_string) < 32:
                console.print(f"[bold red]Error:[/] Text does not contain valid hidden data")
                return None
            
            # Extract length information
            length_binary = binary_string[:32]
            data_binary = binary_string[32:]
            
            length = int(length_binary, 2)
            
            # Check if we have enough bits for the data
            if len(data_binary) < length * 8:
                console.print(f"[bold red]Error:[/] Text does not contain complete hidden data")
                return None
            
            # Convert binary string to bytes
            data = bytearray()
            for i in range(0, length * 8, 8):
                if i + 8 <= len(data_binary):
                    byte = int(data_binary[i:i+8], 2)
                    data.append(byte)
            
            console.print(f"[bold green]Data extracted successfully:[/] {length} bytes extracted from text using whitespace method")
            return bytes(data)
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def _hide_unicode(self, text, data):
        """Hide data in text using Unicode steganography."""
        try:
            # Convert data to binary string
            binary_string = ''.join(format(byte, '08b') for byte in data)
            
            # Add length information to the beginning
            length = len(data)
            length_binary = format(length, '032b')  # 32 bits for length (4 bytes)
            binary_string = length_binary + binary_string
            
            # Check if we have enough characters to hide the data
            if len(text) < len(binary_string):
                console.print(f"[bold red]Error:[/] Text too small to hide {len(data)} bytes of data")
                return None
            
            # Hide data by replacing characters with similar-looking Unicode characters
            result_text = list(text)
            for i in range(len(binary_string)):
                if i < len(result_text):
                    if binary_string[i] == '1':
                        # Replace with similar-looking Unicode character
                        if result_text[i] == 'a':
                            result_text[i] = 'а'  # Cyrillic 'a'
                        elif result_text[i] == 'e':
                            result_text[i] = 'е'  # Cyrillic 'e'
                        elif result_text[i] == 'o':
                            result_text[i] = 'о'  # Cyrillic 'o'
                        elif result_text[i] == 'p':
                            result_text[i] = 'р'  # Cyrillic 'p'
                        elif result_text[i] == 'c':
                            result_text[i] = 'с'  # Cyrillic 'c'
                        elif result_text[i] == 'x':
                            result_text[i] = 'х'  # Cyrillic 'x'
                        # Add more character replacements as needed
            
            # Join characters back into text
            result_text = ''.join(result_text)
            
            console.print(f"[bold green]Data hidden successfully:[/] {len(data)} bytes hidden in text using Unicode method")
            return result_text
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def _extract_unicode(self, text):
        """Extract hidden data from text using Unicode steganography."""
        console.print("[bold yellow]Warning:[/] Unicode extraction method is not fully implemented yet")
        console.print("[bold blue]Using whitespace method instead[/]")
        return self._extract_whitespace(text)
    
    def _hide_zero_width(self, text, data):
        """Hide data in text using zero-width characters."""
        try:
            # Convert data to binary string
            binary_string = ''.join(format(byte, '08b') for byte in data)
            
            # Add length information to the beginning
            length = len(data)
            length_binary = format(length, '032b')  # 32 bits for length (4 bytes)
            binary_string = length_binary + binary_string
            
            # Define zero-width characters
            zwsp = '\u200B'  # Zero-width space (for 0)
            zwj = '\u200D'   # Zero-width joiner (for 1)
            
            # Convert binary string to zero-width characters
            hidden_data = ''
            for bit in binary_string:
                if bit == '0':
                    hidden_data += zwsp
                else:
                    hidden_data += zwj
            
            # Insert hidden data at a specific position in the text
            # For simplicity, we'll insert it at the beginning
            result_text = hidden_data + text
            
            console.print(f"[bold green]Data hidden successfully:[/] {len(data)} bytes hidden in text using zero-width characters")
            return result_text
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def _extract_zero_width(self, text):
        """Extract hidden data from text using zero-width characters."""
        try:
            # Define zero-width characters
            zwsp = '\u200B'  # Zero-width space (for 0)
            zwj = '\u200D'   # Zero-width joiner (for 1)
            
            # Extract binary string from zero-width characters
            binary_string = ''
            for char in text:
                if char == zwsp:
                    binary_string += '0'
                elif char == zwj:
                    binary_string += '1'
            
            # Check if we have enough bits for length information
            if len(binary_string) < 32:
                console.print(f"[bold red]Error:[/] Text does not contain valid hidden data")
                return None
            
            # Extract length information
            length_binary = binary_string[:32]
            data_binary = binary_string[32:]
            
            length = int(length_binary, 2)
            
            # Check if we have enough bits for the data
            if len(data_binary) < length * 8:
                console.print(f"[bold red]Error:[/] Text does not contain complete hidden data")
                return None
            
            # Convert binary string to bytes
            data = bytearray()
            for i in range(0, length * 8, 8):
                if i + 8 <= len(data_binary):
                    byte = int(data_binary[i:i+8], 2)
                    data.append(byte)
            
            console.print(f"[bold green]Data extracted successfully:[/] {length} bytes extracted from text using zero-width characters")
            return bytes(data)
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def analyze_text(self, text_path):
        """Analyze a text file for potential steganography."""
        console.print(f"[bold blue]Analyzing text for steganography:[/] [bold green]{text_path}[/]")
        
        try:
            # Read the text file
            with open(text_path, 'r', encoding='utf-8') as f:
                text = f.read()
            
            # Check for trailing whitespace
            lines = text.split('\n')
            lines_with_trailing_spaces = 0
            
            for line in lines:
                if line.rstrip() != line:
                    lines_with_trailing_spaces += 1
            
            trailing_spaces_percentage = (lines_with_trailing_spaces / len(lines)) * 100 if lines else 0
            
            console.print(f"[bold]Whitespace Analysis:[/]")
            console.print(f"Lines with trailing spaces: {lines_with_trailing_spaces} out of {len(lines)} ({trailing_spaces_percentage:.2f}%)")
            
            if trailing_spaces_percentage > 50:
                console.print(f"[bold yellow]High percentage of lines with trailing spaces, which may indicate whitespace steganography[/]")
            
            # Check for zero-width characters
            zwsp_count = text.count('\u200B')  # Zero-width space
            zwj_count = text.count('\u200D')   # Zero-width joiner
            zwnj_count = text.count('\u200C')  # Zero-width non-joiner
            
            console.print(f"[bold]Zero-Width Character Analysis:[/]")
            console.print(f"Zero-width spaces: {zwsp_count}")
            console.print(f"Zero-width joiners: {zwj_count}")
            console.print(f"Zero-width non-joiners: {zwnj_count}")
            
            if zwsp_count > 0 or zwj_count > 0 or zwnj_count > 0:
                console.print(f"[bold yellow]Zero-width characters detected, which may indicate zero-width steganography[/]")
            
            # Check for Unicode homoglyphs
            cyrillic_chars = re.findall('[а-яА-Я]', text)
            
            console.print(f"[bold]Unicode Analysis:[/]")
            console.print(f"Cyrillic characters: {len(cyrillic_chars)}")
            
            if len(cyrillic_chars) > 0:
                console.print(f"[bold yellow]Cyrillic characters detected in non-Cyrillic text, which may indicate Unicode steganography[/]")
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
