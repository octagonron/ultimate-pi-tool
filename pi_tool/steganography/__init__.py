"""
Steganography module for the Ultimate PI Tool.

This module provides functionality for hiding and extracting data using various
steganography techniques including image, audio, text, and network steganography.
"""

from .image import ImageSteganography
from .audio import AudioSteganography
from .text import TextSteganography
from .network import NetworkSteganography
from .detector import SteganographyDetector

def handle_stego_command(args):
    """Handle steganography command line arguments and dispatch to appropriate handler."""
    if args.stego_command == "image":
        image_stego = ImageSteganography()
        if args.hide:
            if not args.image or not args.data:
                print("Please provide both image file and data to hide.")
                return
            image_stego.hide_data(args.image, args.data)
        elif args.extract:
            if not args.image:
                print("Please provide an image file to extract data from.")
                return
            image_stego.extract_data(args.image, args.data)
        else:
            print("Please specify either --hide or --extract operation.")
    
    elif args.stego_command == "audio":
        audio_stego = AudioSteganography()
        if args.hide:
            if not args.audio or not args.data:
                print("Please provide both audio file and data to hide.")
                return
            audio_stego.hide_data(args.audio, args.data)
        elif args.extract:
            if not args.audio:
                print("Please provide an audio file to extract data from.")
                return
            audio_stego.extract_data(args.audio, args.data)
        else:
            print("Please specify either --hide or --extract operation.")
    
    elif args.stego_command == "text":
        text_stego = TextSteganography()
        if args.hide:
            if not args.text or not args.data:
                print("Please provide both text file and data to hide.")
                return
            text_stego.hide_data(args.text, args.data, args.method)
        elif args.extract:
            if not args.text:
                print("Please provide a text file to extract data from.")
                return
            text_stego.extract_data(args.text, args.data, args.method)
        else:
            print("Please specify either --hide or --extract operation.")
    
    elif args.stego_command == "network":
        network_stego = NetworkSteganography()
        if args.hide:
            if not args.data:
                print("Please provide data to hide.")
                return
            network_stego.hide_data(args.data, args.protocol, args.destination)
        elif args.extract:
            network_stego.extract_data(args.protocol, args.interface)
        elif args.listen:
            network_stego.listen(args.protocol, args.interface)
        else:
            print("Please specify either --hide, --extract, or --listen operation.")
    
    elif args.stego_command == "detect":
        detector = SteganographyDetector()
        if args.file:
            detector.detect(args.file, args.type)
        else:
            print("Please provide a file to analyze.")
    
    else:
        print(f"Unknown steganography command: {args.stego_command}")
