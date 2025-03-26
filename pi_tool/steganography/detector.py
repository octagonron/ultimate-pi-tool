"""
Steganography Detector module for the Ultimate PI Tool.

This module provides functionality for detecting hidden data in various media
including images, audio, text, and network traffic.
"""

import os
import sys
import numpy as np
from PIL import Image
import wave
import re
from rich.console import Console
from rich.table import Table

console = Console()

class SteganographyDetector:
    """Steganography Detector class for detecting hidden data in various media."""
    
    def __init__(self):
        """Initialize the Steganography Detector module."""
        pass
    
    def detect(self, file_path, file_type=None):
        """Detect potential steganography in a file."""
        console.print(f"[bold blue]Analyzing file for steganography:[/] [bold green]{file_path}[/]")
        
        # Determine file type if not specified
        if not file_type:
            file_type = self._determine_file_type(file_path)
        
        # Choose the appropriate method based on file type
        if file_type.lower() == "image":
            return self._detect_image(file_path)
        elif file_type.lower() == "audio":
            return self._detect_audio(file_path)
        elif file_type.lower() == "text":
            return self._detect_text(file_path)
        else:
            console.print(f"[bold red]Error:[/] Unsupported file type: {file_type}")
            return False
    
    def _determine_file_type(self, file_path):
        """Determine the type of file based on extension and content."""
        # Check file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        # Image extensions
        if ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff']:
            return "image"
        
        # Audio extensions
        elif ext in ['.wav', '.mp3', '.flac', '.ogg', '.aac']:
            return "audio"
        
        # Text extensions
        elif ext in ['.txt', '.md', '.html', '.xml', '.json', '.csv']:
            return "text"
        
        # If extension is not recognized, try to determine by content
        try:
            with open(file_path, 'rb') as f:
                header = f.read(12)
                
                # Check for image headers
                if header.startswith(b'\x89PNG'):
                    return "image"
                elif header.startswith(b'\xff\xd8'):
                    return "image"
                elif header.startswith(b'GIF8'):
                    return "image"
                elif header.startswith(b'BM'):
                    return "image"
                
                # Check for audio headers
                elif header.startswith(b'RIFF'):
                    return "audio"
                elif header.startswith(b'ID3'):
                    return "audio"
                elif header.startswith(b'fLaC'):
                    return "audio"
                
                # If no specific header is recognized, check if it's text
                try:
                    with open(file_path, 'r', encoding='utf-8') as text_file:
                        text_file.read(1024)  # Try to read as text
                    return "text"
                except UnicodeDecodeError:
                    # Not a text file
                    pass
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Error determining file type: {str(e)}")
        
        # Default to unknown
        console.print(f"[bold yellow]Warning:[/] Could not determine file type, please specify manually")
        return "unknown"
    
    def _detect_image(self, image_path):
        """Detect potential steganography in an image."""
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
            suspicious = False
            reasons = []
            
            if 45 <= lsb_0_percentage <= 55 and 45 <= lsb_1_percentage <= 55:
                suspicious = True
                reasons.append("LSB distribution is close to 50/50, which may indicate hidden data")
            
            # Check file size
            file_size = os.path.getsize(image_path)
            expected_size = (height * width * channels) / 8
            size_ratio = file_size / expected_size
            
            console.print(f"[bold]File Size Analysis:[/]")
            console.print(f"Actual size: {file_size} bytes")
            console.print(f"Expected size: {expected_size:.2f} bytes")
            console.print(f"Size ratio: {size_ratio:.2f}")
            
            if size_ratio > 1.5:
                suspicious = True
                reasons.append("File size is larger than expected, which may indicate hidden data")
            
            # Check for color abnormalities
            # This is a simplified version - a real implementation would be more sophisticated
            color_variance = np.var(img_array)
            console.print(f"[bold]Color Analysis:[/]")
            console.print(f"Color variance: {color_variance:.2f}")
            
            if color_variance < 100:
                suspicious = True
                reasons.append("Low color variance, which may indicate manipulation")
            
            # Display results
            if suspicious:
                console.print(f"[bold red]Suspicious![/] This image may contain hidden data")
                for reason in reasons:
                    console.print(f"[bold yellow]- {reason}[/]")
            else:
                console.print(f"[bold green]No obvious signs of steganography detected[/]")
            
            return suspicious
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def _detect_audio(self, audio_path):
        """Detect potential steganography in an audio file."""
        console.print(f"[bold blue]Analyzing audio for steganography:[/] [bold green]{audio_path}[/]")
        
        try:
            # Check if it's a WAV file
            if not audio_path.lower().endswith('.wav'):
                console.print(f"[bold yellow]Warning:[/] Only WAV files are fully supported for analysis")
                console.print(f"[bold blue]Basic file analysis will be performed instead[/]")
                
                # Perform basic file analysis
                file_size = os.path.getsize(audio_path)
                console.print(f"[bold]File Size:[/] {file_size} bytes")
                
                # Read file header
                with open(audio_path, 'rb') as f:
                    header = f.read(128)
                    console.print(f"[bold]File Header (hex):[/] {header.hex()[:100]}...")
                
                return False
            
            # Open the audio file
            with wave.open(audio_path, 'rb') as wav:
                # Get audio parameters
                n_channels = wav.getnchannels()
                sample_width = wav.getsampwidth()
                frame_rate = wav.getframerate()
                n_frames = wav.getnframes()
                
                # Read all frames
                frames = wav.readframes(n_frames)
            
            # Convert frames to numpy array
            if sample_width == 1:
                # 8-bit audio (unsigned)
                audio_array = np.frombuffer(frames, dtype=np.uint8)
            elif sample_width == 2:
                # 16-bit audio (signed)
                audio_array = np.frombuffer(frames, dtype=np.int16)
            else:
                console.print(f"[bold red]Error:[/] Unsupported sample width: {sample_width}")
                return False
            
            # Display basic audio information
            console.print(f"[bold]Audio Information:[/]")
            console.print(f"Channels: {n_channels}")
            console.print(f"Sample Width: {sample_width} bytes")
            console.print(f"Frame Rate: {frame_rate} Hz")
            console.print(f"Number of Frames: {n_frames}")
            console.print(f"Duration: {n_frames / frame_rate:.2f} seconds")
            
            # Analyze LSB distribution
            lsb_0_count = 0
            lsb_1_count = 0
            
            for i in range(len(audio_array)):
                if audio_array[i] & 1 == 0:
                    lsb_0_count += 1
                else:
                    lsb_1_count += 1
            
            lsb_0_percentage = (lsb_0_count / len(audio_array)) * 100
            lsb_1_percentage = (lsb_1_count / len(audio_array)) * 100
            
            console.print(f"[bold]LSB Analysis:[/]")
            console.print(f"LSB 0s: {lsb_0_count} ({lsb_0_percentage:.2f}%)")
            console.print(f"LSB 1s: {lsb_1_count} ({lsb_1_percentage:.2f}%)")
            
            # Check for suspicious LSB distribution
            suspicious = False
            reasons = []
            
            if 45 <= lsb_0_percentage <= 55 and 45 <= lsb_1_percentage <= 55:
                suspicious = True
                reasons.append("LSB distribution is close to 50/50, which may indicate hidden data")
            
            # Check file size
            file_size = os.path.getsize(audio_path)
            expected_size = n_frames * n_channels * sample_width
            size_ratio = file_size / expected_size
            
            console.print(f"[bold]File Size Analysis:[/]")
            console.print(f"Actual size: {file_size} bytes")
            console.print(f"Expected size: {expected_size} bytes")
            console.print(f"Size ratio: {size_ratio:.2f}")
            
            if size_ratio > 1.1:
                suspicious = True
                reasons.append("File size is larger than expected, which may indicate hidden data")
            
            # Check for unusual frequency patterns
            # This is a simplified version - a real implementation would use FFT
            audio_variance = np.var(audio_array)
            console.print(f"[bold]Audio Analysis:[/]")
            console.print(f"Audio variance: {audio_variance:.2f}")
            
            if audio_variance < 1000:
                suspicious = True
                reasons.append("Low audio variance, which may indicate manipulation")
            
            # Display results
            if suspicious:
                console.print(f"[bold red]Suspicious![/] This audio file may contain hidden data")
                for reason in reasons:
                    console.print(f"[bold yellow]- {reason}[/]")
            else:
                console.print(f"[bold green]No obvious signs of steganography detected[/]")
            
            return suspicious
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def _detect_text(self, text_path):
        """Detect potential steganography in a text file."""
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
            
            # Check for zero-width characters
            zwsp_count = text.count('\u200B')  # Zero-width space
            zwj_count = text.count('\u200D')   # Zero-width joiner
            zwnj_count = text.count('\u200C')  # Zero-width non-joiner
            
            console.print(f"[bold]Zero-Width Character Analysis:[/]")
            console.print(f"Zero-width spaces: {zwsp_count}")
            console.print(f"Zero-width joiners: {zwj_count}")
            console.print(f"Zero-width non-joiners: {zwnj_count}")
            
            # Check for Unicode homoglyphs
            cyrillic_chars = re.findall('[а-яА-Я]', text)
            
            console.print(f"[bold]Unicode Analysis:[/]")
            console.print(f"Cyrillic characters: {len(cyrillic_chars)}")
            
            # Check for suspicious patterns
            suspicious = False
            reasons = []
            
            if trailing_spaces_percentage > 50:
                suspicious = True
                reasons.append("High percentage of lines with trailing spaces, which may indicate whitespace steganography")
            
            if zwsp_count > 0 or zwj_count > 0 or zwnj_count > 0:
                suspicious = True
                reasons.append(f"Zero-width characters detected ({zwsp_count + zwj_count + zwnj_count} total), which may indicate zero-width steganography")
            
            if len(cyrillic_chars) > 0:
                suspicious = True
                reasons.append(f"Cyrillic characters detected ({len(cyrillic_chars)} total) in non-Cyrillic text, which may indicate Unicode steganography")
            
            # Display results
            if suspicious:
                console.print(f"[bold red]Suspicious![/] This text file may contain hidden data")
                for reason in reasons:
                    console.print(f"[bold yellow]- {reason}[/]")
            else:
                console.print(f"[bold green]No obvious signs of steganography detected[/]")
            
            return suspicious
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def analyze_file(self, file_path):
        """Perform a comprehensive analysis of a file for steganography."""
        console.print(f"[bold blue]Performing comprehensive steganography analysis on:[/] [bold green]{file_path}[/]")
        
        # Determine file type
        file_type = self._determine_file_type(file_path)
        console.print(f"[bold]Detected file type:[/] {file_type}")
        
        # Create results table
        table = Table(title=f"Steganography Analysis Results: {os.path.basename(file_path)}")
        table.add_column("Test", style="cyan")
        table.add_column("Result", style="green")
        table.add_column("Risk", style="yellow")
        
        # Perform basic file analysis
        file_size = os.path.getsize(file_path)
        table.add_row("File Size", f"{file_size} bytes", "Low")
        
        # Perform type-specific analysis
        if file_type == "image":
            # Analyze image
            img = Image.open(file_path)
            
            # Check format and mode
            table.add_row("Image Format", img.format, "Low")
            table.add_row("Image Mode", img.mode, "Low")
            
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Analyze LSB distribution
            img_array = np.array(img)
            height, width, channels = img_array.shape
            total_pixels = height * width * channels
            
            lsb_0_count = 0
            lsb_1_count = 0
            
            for h in range(height):
                for w in range(width):
                    for c in range(channels):
                        if img_array[h, w, c] & 1 == 0:
                            lsb_0_count += 1
                        else:
                            lsb_1_count += 1
            
            lsb_0_percentage = (lsb_0_count / total_pixels) * 100
            lsb_1_percentage = (lsb_1_count / total_pixels) * 100
            
            lsb_risk = "Low"
            if 45 <= lsb_0_percentage <= 55 and 45 <= lsb_1_percentage <= 55:
                lsb_risk = "High"
            
            table.add_row("LSB Distribution", f"0s: {lsb_0_percentage:.2f}%, 1s: {lsb_1_percentage:.2f}%", lsb_risk)
            
        elif file_type == "audio":
            # Check if it's a WAV file
            if file_path.lower().endswith('.wav'):
                # Analyze WAV file
                with wave.open(file_path, 'rb') as wav:
                    n_channels = wav.getnchannels()
                    sample_width = wav.getsampwidth()
                    frame_rate = wav.getframerate()
                    n_frames = wav.getnframes()
                
                table.add_row("Audio Channels", str(n_channels), "Low")
                table.add_row("Sample Width", f"{sample_width} bytes", "Low")
                table.add_row("Frame Rate", f"{frame_rate} Hz", "Low")
                table.add_row("Duration", f"{n_frames / frame_rate:.2f} seconds", "Low")
            else:
                table.add_row("Audio Format", "Non-WAV (limited analysis)", "Medium")
        
        elif file_type == "text":
            # Analyze text file
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
            
            # Check for trailing whitespace
            lines = text.split('\n')
            lines_with_trailing_spaces = 0
            
            for line in lines:
                if line.rstrip() != line:
                    lines_with_trailing_spaces += 1
            
            trailing_spaces_percentage = (lines_with_trailing_spaces / len(lines)) * 100 if lines else 0
            
            whitespace_risk = "Low"
            if trailing_spaces_percentage > 50:
                whitespace_risk = "High"
            
            table.add_row("Trailing Whitespace", f"{trailing_spaces_percentage:.2f}% of lines", whitespace_risk)
            
            # Check for zero-width characters
            zwsp_count = text.count('\u200B')  # Zero-width space
            zwj_count = text.count('\u200D')   # Zero-width joiner
            zwnj_count = text.count('\u200C')  # Zero-width non-joiner
            
            zw_total = zwsp_count + zwj_count + zwnj_count
            zw_risk = "Low"
            if zw_total > 0:
                zw_risk = "High"
            
            table.add_row("Zero-Width Characters", str(zw_total), zw_risk)
            
            # Check for Unicode homoglyphs
            cyrillic_chars = re.findall('[а-яА-Я]', text)
            
            cyrillic_risk = "Low"
            if len(cyrillic_chars) > 0:
                cyrillic_risk = "High"
            
            table.add_row("Cyrillic Characters", str(len(cyrillic_chars)), cyrillic_risk)
        
        # Display results
        console.print(table)
        
        # Determine overall risk
        high_risk_count = 0
        medium_risk_count = 0
        
        for row in table.rows:
            if row.cells[2].renderable == "High":
                high_risk_count += 1
            elif row.cells[2].renderable == "Medium":
                medium_risk_count += 1
        
        if high_risk_count > 0:
            console.print(f"[bold red]High Risk![/] This file likely contains hidden data")
            return True
        elif medium_risk_count > 0:
            console.print(f"[bold yellow]Medium Risk![/] This file may contain hidden data")
            return True
        else:
            console.print(f"[bold green]Low Risk![/] No obvious signs of steganography detected")
            return False
