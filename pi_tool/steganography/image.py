"""
Image Steganography module for the Ultimate PI Tool.

This module provides functionality for hiding and extracting data in images
using various steganography techniques including LSB (Least Significant Bit).
"""

import os
import sys
import numpy as np
from PIL import Image
from rich.console import Console
import binascii

console = Console()

class ImageSteganography:
    """Image Steganography class for hiding and extracting data in images."""
    
    def __init__(self):
        """Initialize the Image Steganography module."""
        pass
    
    def hide_data(self, image_path, data, output_path=None, method="lsb"):
        """Hide data in an image using the specified method."""
        console.print(f"[bold blue]Hiding data in image:[/] [bold green]{image_path}[/]")
        
        # Determine output path if not specified
        if not output_path:
            filename, ext = os.path.splitext(image_path)
            output_path = f"{filename}_stego{ext}"
        
        # Choose the appropriate method
        if method.lower() == "lsb":
            success = self._hide_lsb(image_path, data, output_path)
        else:
            console.print(f"[bold red]Error:[/] Unsupported method: {method}")
            return False
        
        if success:
            console.print(f"[bold green]Success![/] Data hidden in image: [bold]{output_path}[/]")
            return True
        else:
            console.print(f"[bold red]Error:[/] Failed to hide data in image")
            return False
    
    def extract_data(self, image_path, output_file=None, method="lsb"):
        """Extract hidden data from an image using the specified method."""
        console.print(f"[bold blue]Extracting data from image:[/] [bold green]{image_path}[/]")
        
        # Choose the appropriate method
        if method.lower() == "lsb":
            data = self._extract_lsb(image_path)
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
            console.print(f"[bold red]Error:[/] Failed to extract data from image")
            return False
    
    def _hide_lsb(self, image_path, data, output_path):
        """Hide data in an image using the LSB (Least Significant Bit) method."""
        try:
            # Open the image
            img = Image.open(image_path)
            
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Convert image to numpy array
            img_array = np.array(img)
            
            # Get image dimensions
            height, width, channels = img_array.shape
            
            # Convert data to binary
            if isinstance(data, str):
                # If data is a file path, read the file
                if os.path.isfile(data):
                    with open(data, 'rb') as f:
                        binary_data = f.read()
                else:
                    # Otherwise, treat as text
                    binary_data = data.encode('utf-8')
            else:
                binary_data = data
            
            # Add length information to the data
            length = len(binary_data)
            length_bytes = length.to_bytes(4, byteorder='big')
            binary_data = length_bytes + binary_data
            
            # Convert binary data to bit array
            bit_array = []
            for byte in binary_data:
                for bit in range(8):
                    bit_array.append((byte >> bit) & 1)
            
            # Check if the image can hold the data
            max_bits = height * width * channels
            if len(bit_array) > max_bits:
                console.print(f"[bold red]Error:[/] Image too small to hide {len(binary_data)} bytes of data")
                return False
            
            # Embed data in the LSB of each pixel value
            bit_index = 0
            for h in range(height):
                for w in range(width):
                    for c in range(channels):
                        if bit_index < len(bit_array):
                            # Clear the LSB and set it to the data bit
                            img_array[h, w, c] = (img_array[h, w, c] & 0xFE) | bit_array[bit_index]
                            bit_index += 1
                        else:
                            break
                    if bit_index >= len(bit_array):
                        break
                if bit_index >= len(bit_array):
                    break
            
            # Save the modified image
            result_img = Image.fromarray(img_array)
            result_img.save(output_path)
            
            console.print(f"[bold green]Data hidden successfully:[/] {len(binary_data)} bytes hidden in image")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def _extract_lsb(self, image_path):
        """Extract hidden data from an image using the LSB (Least Significant Bit) method."""
        try:
            # Open the image
            img = Image.open(image_path)
            
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Convert image to numpy array
            img_array = np.array(img)
            
            # Get image dimensions
            height, width, channels = img_array.shape
            
            # Extract LSB from each pixel value
            bit_array = []
            for h in range(height):
                for w in range(width):
                    for c in range(channels):
                        bit_array.append(img_array[h, w, c] & 1)
            
            # Convert bit array to bytes
            byte_array = bytearray()
            for i in range(0, len(bit_array), 8):
                if i + 8 <= len(bit_array):
                    byte = 0
                    for j in range(8):
                        byte |= bit_array[i + j] << j
                    byte_array.append(byte)
            
            # Extract length information
            if len(byte_array) < 4:
                console.print(f"[bold red]Error:[/] Image does not contain valid hidden data")
                return None
            
            length = int.from_bytes(byte_array[:4], byteorder='big')
            
            # Check if the extracted length is valid
            if length <= 0 or length > len(byte_array) - 4:
                console.print(f"[bold red]Error:[/] Invalid data length: {length}")
                return None
            
            # Extract the actual data
            data = byte_array[4:4+length]
            
            console.print(f"[bold green]Data extracted successfully:[/] {length} bytes extracted from image")
            return bytes(data)
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def analyze_image(self, image_path):
        """Analyze an image for potential steganography."""
        console.print(f"[bold blue]Analyzing image for steganography:[/] [bold green]{image_path}[/]")
        
        try:
            # Open the image
            img = Image.open(image_path)
            
            # Get basic image information
            console.print(f"[bold]Image Information:[/]")
            console.print(f"Format: {img.format}")
            console.print(f"Mode: {img.mode}")
            console.print(f"Size: {img.size}")
            
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Convert image to numpy array
            img_array = np.array(img)
            
            # Analyze LSB distribution
            lsb_0_count = 0
            lsb_1_count = 0
            
            height, width, channels = img_array.shape
            total_pixels = height * width * channels
            
            for h in range(height):
                for w in range(width):
                    for c in range(channels):
                        if img_array[h, w, c] & 1 == 0:
                            lsb_0_count += 1
                        else:
                            lsb_1_count += 1
            
            lsb_0_percentage = (lsb_0_count / total_pixels) * 100
            lsb_1_percentage = (lsb_1_count / total_pixels) * 100
            
            console.print(f"[bold]LSB Analysis:[/]")
            console.print(f"LSB 0s: {lsb_0_count} ({lsb_0_percentage:.2f}%)")
            console.print(f"LSB 1s: {lsb_1_count} ({lsb_1_percentage:.2f}%)")
            
            # Check for suspicious LSB distribution
            if 45 <= lsb_0_percentage <= 55 and 45 <= lsb_1_percentage <= 55:
                console.print(f"[bold yellow]LSB distribution is close to 50/50, which may indicate hidden data[/]")
            
            # Check file size
            file_size = os.path.getsize(image_path)
            expected_size = (height * width * channels) / 8
            size_ratio = file_size / expected_size
            
            console.print(f"[bold]File Size Analysis:[/]")
            console.print(f"Actual size: {file_size} bytes")
            console.print(f"Expected size: {expected_size:.2f} bytes")
            console.print(f"Size ratio: {size_ratio:.2f}")
            
            if size_ratio > 1.5:
                console.print(f"[bold yellow]File size is larger than expected, which may indicate hidden data[/]")
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
