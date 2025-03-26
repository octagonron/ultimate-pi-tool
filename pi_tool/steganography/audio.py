"""
Audio Steganography module for the Ultimate PI Tool.

This module provides functionality for hiding and extracting data in audio files
using various steganography techniques including phase coding and LSB methods.
"""

import os
import sys
import numpy as np
import wave
from rich.console import Console

console = Console()

class AudioSteganography:
    """Audio Steganography class for hiding and extracting data in audio files."""
    
    def __init__(self):
        """Initialize the Audio Steganography module."""
        pass
    
    def hide_data(self, audio_path, data, output_path=None, method="lsb"):
        """Hide data in an audio file using the specified method."""
        console.print(f"[bold blue]Hiding data in audio:[/] [bold green]{audio_path}[/]")
        
        # Determine output path if not specified
        if not output_path:
            filename, ext = os.path.splitext(audio_path)
            output_path = f"{filename}_stego{ext}"
        
        # Choose the appropriate method
        if method.lower() == "lsb":
            success = self._hide_lsb(audio_path, data, output_path)
        elif method.lower() == "phase":
            success = self._hide_phase(audio_path, data, output_path)
        else:
            console.print(f"[bold red]Error:[/] Unsupported method: {method}")
            return False
        
        if success:
            console.print(f"[bold green]Success![/] Data hidden in audio: [bold]{output_path}[/]")
            return True
        else:
            console.print(f"[bold red]Error:[/] Failed to hide data in audio")
            return False
    
    def extract_data(self, audio_path, output_file=None, method="lsb"):
        """Extract hidden data from an audio file using the specified method."""
        console.print(f"[bold blue]Extracting data from audio:[/] [bold green]{audio_path}[/]")
        
        # Choose the appropriate method
        if method.lower() == "lsb":
            data = self._extract_lsb(audio_path)
        elif method.lower() == "phase":
            data = self._extract_phase(audio_path)
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
            console.print(f"[bold red]Error:[/] Failed to extract data from audio")
            return False
    
    def _hide_lsb(self, audio_path, data, output_path):
        """Hide data in an audio file using the LSB (Least Significant Bit) method."""
        try:
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
            
            # Check if the audio can hold the data
            max_bits = len(audio_array)
            if len(bit_array) > max_bits:
                console.print(f"[bold red]Error:[/] Audio too small to hide {len(binary_data)} bytes of data")
                return False
            
            # Embed data in the LSB of each audio sample
            for i in range(len(bit_array)):
                # Clear the LSB and set it to the data bit
                audio_array[i] = (audio_array[i] & ~1) | bit_array[i]
            
            # Convert back to bytes
            modified_frames = audio_array.tobytes()
            
            # Save the modified audio
            with wave.open(output_path, 'wb') as wav:
                wav.setnchannels(n_channels)
                wav.setsampwidth(sample_width)
                wav.setframerate(frame_rate)
                wav.writeframes(modified_frames)
            
            console.print(f"[bold green]Data hidden successfully:[/] {len(binary_data)} bytes hidden in audio")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def _extract_lsb(self, audio_path):
        """Extract hidden data from an audio file using the LSB (Least Significant Bit) method."""
        try:
            # Open the audio file
            with wave.open(audio_path, 'rb') as wav:
                # Get audio parameters
                sample_width = wav.getsampwidth()
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
                return None
            
            # Extract LSB from each audio sample
            bit_array = []
            for i in range(len(audio_array)):
                bit_array.append(audio_array[i] & 1)
            
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
                console.print(f"[bold red]Error:[/] Audio does not contain valid hidden data")
                return None
            
            length = int.from_bytes(byte_array[:4], byteorder='big')
            
            # Check if the extracted length is valid
            if length <= 0 or length > len(byte_array) - 4:
                console.print(f"[bold red]Error:[/] Invalid data length: {length}")
                return None
            
            # Extract the actual data
            data = byte_array[4:4+length]
            
            console.print(f"[bold green]Data extracted successfully:[/] {length} bytes extracted from audio")
            return bytes(data)
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def _hide_phase(self, audio_path, data, output_path):
        """Hide data in an audio file using the phase coding method."""
        console.print("[bold yellow]Warning:[/] Phase coding method is not fully implemented yet")
        console.print("[bold blue]Using LSB method instead[/]")
        return self._hide_lsb(audio_path, data, output_path)
    
    def _extract_phase(self, audio_path):
        """Extract hidden data from an audio file using the phase coding method."""
        console.print("[bold yellow]Warning:[/] Phase coding method is not fully implemented yet")
        console.print("[bold blue]Using LSB method instead[/]")
        return self._extract_lsb(audio_path)
    
    def analyze_audio(self, audio_path):
        """Analyze an audio file for potential steganography."""
        console.print(f"[bold blue]Analyzing audio for steganography:[/] [bold green]{audio_path}[/]")
        
        try:
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
            if 45 <= lsb_0_percentage <= 55 and 45 <= lsb_1_percentage <= 55:
                console.print(f"[bold yellow]LSB distribution is close to 50/50, which may indicate hidden data[/]")
            
            # Check file size
            file_size = os.path.getsize(audio_path)
            expected_size = n_frames * n_channels * sample_width
            size_ratio = file_size / expected_size
            
            console.print(f"[bold]File Size Analysis:[/]")
            console.print(f"Actual size: {file_size} bytes")
            console.print(f"Expected size: {expected_size} bytes")
            console.print(f"Size ratio: {size_ratio:.2f}")
            
            if size_ratio > 1.1:
                console.print(f"[bold yellow]File size is larger than expected, which may indicate hidden data[/]")
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
