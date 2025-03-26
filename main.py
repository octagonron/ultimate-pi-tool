#!/usr/bin/env python3
"""
Ultimate PI Tool - A comprehensive platform for private investigation and security analysis

This tool combines OSINT, steganography, cryptography, tracking/reporting, and various 
generators/decoders into a unified system.
"""

import os
import sys
import argparse
import logging
from rich.console import Console
from rich.logging import RichHandler
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("pi_tool")

# Load environment variables
load_dotenv()

# Initialize console
console = Console()

def setup_argparse():
    """Setup command line argument parsing"""
    parser = argparse.ArgumentParser(
        description="Ultimate PI Tool - A comprehensive platform for private investigation and security analysis"
    )
    
    # Main command groups
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # OSINT commands
    osint_parser = subparsers.add_parser("osint", help="OSINT tools")
    osint_subparsers = osint_parser.add_subparsers(dest="osint_command")
    
    # LinkedIn OSINT
    linkedin_parser = osint_subparsers.add_parser("linkedin", help="LinkedIn OSINT tools")
    linkedin_parser.add_argument("--username", help="LinkedIn username to investigate")
    linkedin_parser.add_argument("--search", help="Search LinkedIn for people")
    
    # Twitter OSINT
    twitter_parser = osint_subparsers.add_parser("twitter", help="Twitter OSINT tools")
    twitter_parser.add_argument("--username", help="Twitter username to investigate")
    twitter_parser.add_argument("--search", help="Search Twitter for tweets")
    twitter_parser.add_argument("--count", type=int, default=20, help="Number of tweets to retrieve")
    
    # Email OSINT
    email_parser = osint_subparsers.add_parser("email", help="Email OSINT tools")
    email_parser.add_argument("--address", help="Email address to investigate")
    
    # Domain OSINT
    domain_parser = osint_subparsers.add_parser("domain", help="Domain OSINT tools")
    domain_parser.add_argument("--name", help="Domain name to investigate")
    
    # Steganography commands
    stego_parser = subparsers.add_parser("stego", help="Steganography tools")
    stego_subparsers = stego_parser.add_subparsers(dest="stego_command")
    
    # Image steganography
    img_stego_parser = stego_subparsers.add_parser("image", help="Image steganography tools")
    img_stego_parser.add_argument("--hide", action="store_true", help="Hide data in image")
    img_stego_parser.add_argument("--extract", action="store_true", help="Extract data from image")
    img_stego_parser.add_argument("--image", help="Image file path")
    img_stego_parser.add_argument("--data", help="Data to hide or file to save extracted data")
    
    # Audio steganography
    audio_stego_parser = stego_subparsers.add_parser("audio", help="Audio steganography tools")
    audio_stego_parser.add_argument("--hide", action="store_true", help="Hide data in audio")
    audio_stego_parser.add_argument("--extract", action="store_true", help="Extract data from audio")
    audio_stego_parser.add_argument("--audio", help="Audio file path")
    audio_stego_parser.add_argument("--data", help="Data to hide or file to save extracted data")
    
    # Cryptography commands
    crypto_parser = subparsers.add_parser("crypto", help="Cryptography tools")
    crypto_subparsers = crypto_parser.add_subparsers(dest="crypto_command")
    
    # Encryption/Decryption
    encrypt_parser = crypto_subparsers.add_parser("encrypt", help="Encryption tools")
    encrypt_parser.add_argument("--method", choices=["aes", "rsa"], default="aes", help="Encryption method")
    encrypt_parser.add_argument("--key", help="Encryption key or key file")
    encrypt_parser.add_argument("--input", help="Input file or text")
    encrypt_parser.add_argument("--output", help="Output file")
    
    decrypt_parser = crypto_subparsers.add_parser("decrypt", help="Decryption tools")
    decrypt_parser.add_argument("--method", choices=["aes", "rsa"], default="aes", help="Decryption method")
    decrypt_parser.add_argument("--key", help="Decryption key or key file")
    decrypt_parser.add_argument("--input", help="Input file or text")
    decrypt_parser.add_argument("--output", help="Output file")
    
    # Hashing
    hash_parser = crypto_subparsers.add_parser("hash", help="Hashing tools")
    hash_parser.add_argument("--algorithm", choices=["md5", "sha1", "sha256", "sha512"], default="sha256", help="Hash algorithm")
    hash_parser.add_argument("--input", help="Input file or text")
    
    # Tracking and reporting commands
    track_parser = subparsers.add_parser("track", help="Tracking and reporting tools")
    track_subparsers = track_parser.add_subparsers(dest="track_command")
    
    # Background report
    bg_report_parser = track_subparsers.add_parser("report", help="Background report tools")
    bg_report_parser.add_argument("--name", help="Person name")
    bg_report_parser.add_argument("--output", help="Output report file")
    
    # Cross-reference
    xref_parser = track_subparsers.add_parser("xref", help="Cross-reference tools")
    xref_parser.add_argument("--input", help="Input data file")
    xref_parser.add_argument("--output", help="Output visualization file")
    
    # Generator and decoder commands
    gen_parser = subparsers.add_parser("generate", help="Generator tools")
    gen_subparsers = gen_parser.add_subparsers(dest="gen_command")
    
    # Username generator
    username_parser = gen_subparsers.add_parser("username", help="Username generator")
    username_parser.add_argument("--name", help="Base name")
    username_parser.add_argument("--count", type=int, default=10, help="Number of usernames to generate")
    
    # Email generator
    email_gen_parser = gen_subparsers.add_parser("email", help="Email generator")
    email_gen_parser.add_argument("--name", help="Base name")
    email_gen_parser.add_argument("--count", type=int, default=10, help="Number of emails to generate")
    
    # Decoder commands
    decode_parser = subparsers.add_parser("decode", help="Decoder tools")
    decode_parser.add_argument("--type", choices=["base64", "hex", "url", "html"], help="Decode type")
    decode_parser.add_argument("--input", help="Input to decode")
    
    # Web interface command
    web_parser = subparsers.add_parser("web", help="Start web interface")
    web_parser.add_argument("--port", type=int, default=8080, help="Port to run web interface on")
    web_parser.add_argument("--host", default="127.0.0.1", help="Host to run web interface on")
    
    return parser

def main():
    """Main entry point for the application"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    try:
        # Import modules only when needed to improve startup time
        if args.command == "osint":
            from pi_tool.osint import handle_osint_command
            handle_osint_command(args)
        elif args.command == "stego":
            from pi_tool.steganography import handle_stego_command
            handle_stego_command(args)
        elif args.command == "crypto":
            from pi_tool.cryptography import handle_crypto_command
            handle_crypto_command(args)
        elif args.command == "track":
            from pi_tool.tracking import handle_track_command
            handle_track_command(args)
        elif args.command == "generate":
            from pi_tool.generators import handle_gen_command
            handle_gen_command(args)
        elif args.command == "decode":
            from pi_tool.decoders import handle_decode_command
            handle_decode_command(args)
        elif args.command == "web":
            from pi_tool.web import start_web_interface
            start_web_interface(args.host, args.port)
        else:
            console.print("[bold red]Unknown command:[/] {}".format(args.command))
            parser.print_help()
    except ImportError as e:
        console.print("[bold red]Error:[/] {}".format(str(e)))
        console.print("Make sure you have installed all required dependencies:")
        console.print("pip install -r requirements.txt")
    except Exception as e:
        logger.exception("An error occurred")
        console.print("[bold red]Error:[/] {}".format(str(e)))

if __name__ == "__main__":
    main()
