#!/usr/bin/env python3
"""
Ultimate PI Tool - Command Line Interface

This is the main entry point for the command-line interface of the Ultimate PI Tool.
It provides access to all components through a unified command structure.
"""

import os
import sys
import argparse
import logging
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

# Create console for rich output
console = Console()

# Import components
try:
    # Add parent directory to path to allow imports
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    
    # Import OSINT components
    from pi_tool.osint import linkedin, twitter, email, domain, username, breaches
    
    # Import steganography components
    from pi_tool.steganography import image, audio, text, network, detector
    
    # Import cryptography components
    from pi_tool.cryptography import symmetric, asymmetric, hashing, password, signatures, keys
    
    # Import tracking components
    from pi_tool.tracking import camera, alias, reports, crossref, visualize, timeline
    
    # Import generator components
    from pi_tool.generators import username as username_gen
    from pi_tool.generators import email as email_gen
    from pi_tool.generators import password as password_gen
    from pi_tool.generators import identity, document
    
    # Import decoder components
    from pi_tool.decoders import decoders
    
    # Import network reconnaissance components
    from pi_tool.network import NetworkRecon
    
except ImportError as e:
    console.print(f"[bold red]Error importing components:[/] {str(e)}")
    console.print("[yellow]Make sure you're running from the project root directory.[/]")
    sys.exit(1)

def print_banner():
    """Print the tool banner."""
    banner = """
██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗    ██████╗ ██╗    ████████╗ ██████╗  ██████╗ ██╗     
██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝    ██╔══██╗██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗      ██████╔╝██║       ██║   ██║   ██║██║   ██║██║     
██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝      ██╔═══╝ ██║       ██║   ██║   ██║██║   ██║██║     
╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗    ██║     ██║       ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝    ╚═╝     ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
                                                                                                                      
"""
    console.print(Panel(banner, border_style="blue", title="Ultimate PI Tool"))
    console.print("Combining OSINT, Steganography, Cryptography, Tracking, and more for comprehensive investigations")
    console.print("Version 1.0.0\n")

def setup_osint_parser(subparsers):
    """Setup the OSINT subcommand parser."""
    osint_parser = subparsers.add_parser('osint', help='Open Source Intelligence tools')
    osint_subparsers = osint_parser.add_subparsers(dest='osint_command', help='OSINT command')
    
    # LinkedIn commands
    linkedin_parser = osint_subparsers.add_parser('linkedin', help='LinkedIn OSINT tools')
    linkedin_subparsers = linkedin_parser.add_subparsers(dest='linkedin_command', help='LinkedIn command')
    
    profile_parser = linkedin_subparsers.add_parser('profile', help='Get LinkedIn profile by username')
    profile_parser.add_argument('username', help='LinkedIn username')
    
    search_parser = linkedin_subparsers.add_parser('search', help='Search LinkedIn for people')
    search_parser.add_argument('keywords', help='Keywords to search for')
    search_parser.add_argument('--first-name', help='First name to search for')
    search_parser.add_argument('--last-name', help='Last name to search for')
    search_parser.add_argument('--school', help='School to search for')
    search_parser.add_argument('--title', help='Title to search for')
    search_parser.add_argument('--company', help='Company to search for')
    
    # Twitter commands
    twitter_parser = osint_subparsers.add_parser('twitter', help='Twitter OSINT tools')
    twitter_subparsers = twitter_parser.add_subparsers(dest='twitter_command', help='Twitter command')
    
    profile_parser = twitter_subparsers.add_parser('profile', help='Get Twitter profile by username')
    profile_parser.add_argument('username', help='Twitter username')
    
    search_parser = twitter_subparsers.add_parser('search', help='Search Twitter for tweets')
    search_parser.add_argument('query', help='Query to search for')
    search_parser.add_argument('--count', type=int, default=20, help='Number of tweets to return')
    search_parser.add_argument('--type', choices=['Top', 'Latest', 'Photos', 'Videos', 'People'], default='Top', help='Type of search')
    
    tweets_parser = twitter_subparsers.add_parser('tweets', help='Get tweets from a user')
    tweets_parser.add_argument('username', help='Twitter username')
    tweets_parser.add_argument('--count', type=int, default=20, help='Number of tweets to return')
    
    # Email commands
    email_parser = osint_subparsers.add_parser('email', help='Email OSINT tools')
    email_subparsers = email_parser.add_subparsers(dest='email_command', help='Email command')
    
    validate_parser = email_subparsers.add_parser('validate', help='Validate an email address')
    validate_parser.add_argument('email', help='Email address to validate')
    
    reputation_parser = email_subparsers.add_parser('reputation', help='Check email reputation')
    reputation_parser.add_argument('email', help='Email address to check')
    
    breach_parser = email_subparsers.add_parser('breach', help='Check if email was in a data breach')
    breach_parser.add_argument('email', help='Email address to check')
    
    # Domain commands
    domain_parser = osint_subparsers.add_parser('domain', help='Domain OSINT tools')
    domain_subparsers = domain_parser.add_subparsers(dest='domain_command', help='Domain command')
    
    whois_parser = domain_subparsers.add_parser('whois', help='Get WHOIS information for a domain')
    whois_parser.add_argument('domain', help='Domain to check')
    
    dns_parser = domain_subparsers.add_parser('dns', help='Get DNS records for a domain')
    dns_parser.add_argument('domain', help='Domain to check')
    dns_parser.add_argument('--record-type', choices=['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'ALL'], default='ALL', help='DNS record type')
    
    ip_parser = domain_subparsers.add_parser('ip', help='Get IP information for a domain')
    ip_parser.add_argument('domain', help='Domain to check')
    
    breach_parser = domain_subparsers.add_parser('breach', help='Check if domain was in a data breach')
    breach_parser.add_argument('domain', help='Domain to check')
    
    # Username commands
    username_parser = osint_subparsers.add_parser('username', help='Username OSINT tools')
    username_subparsers = username_parser.add_subparsers(dest='username_command', help='Username command')
    
    search_parser = username_subparsers.add_parser('search', help='Search for username across platforms')
    search_parser.add_argument('username', help='Username to search for')
    
    variations_parser = username_subparsers.add_parser('variations', help='Generate username variations')
    variations_parser.add_argument('username', help='Base username')
    
    breach_parser = username_subparsers.add_parser('breach', help='Check if username was in a data breach')
    breach_parser.add_argument('username', help='Username to check')
    
    # Breach commands
    breach_parser = osint_subparsers.add_parser('breach', help='Data breach tools')
    breach_subparsers = breach_parser.add_subparsers(dest='breach_command', help='Breach command')
    
    check_parser = breach_subparsers.add_parser('check', help='Check if target was in a data breach')
    check_parser.add_argument('target', help='Target to check (email, username, domain, or IP)')
    check_parser.add_argument('--type', choices=['email', 'username', 'domain', 'ip'], help='Target type (auto-detected if not specified)')
    
    list_parser = breach_subparsers.add_parser('list', help='List known data breaches')
    list_parser.add_argument('--count', type=int, default=10, help='Number of breaches to list')
    
    details_parser = breach_subparsers.add_parser('details', help='Get details about a specific breach')
    details_parser.add_argument('breach_name', help='Name of the breach')

def setup_steg_parser(subparsers):
    """Setup the steganography subcommand parser."""
    steg_parser = subparsers.add_parser('steg', help='Steganography tools')
    steg_subparsers = steg_parser.add_subparsers(dest='steg_command', help='Steganography command')
    
    # Image steganography commands
    image_parser = steg_subparsers.add_parser('image', help='Image steganography tools')
    image_subparsers = image_parser.add_subparsers(dest='image_command', help='Image command')
    
    hide_parser = image_subparsers.add_parser('hide', help='Hide data in an image')
    hide_parser.add_argument('image', help='Image file to use')
    hide_parser.add_argument('data', help='Data to hide (text or file path)')
    hide_parser.add_argument('--output', help='Output image file')
    hide_parser.add_argument('--password', help='Password to encrypt data')
    hide_parser.add_argument('--is-file', action='store_true', help='Treat data as a file path')
    
    extract_parser = image_subparsers.add_parser('extract', help='Extract data from an image')
    extract_parser.add_argument('image', help='Image file to extract from')
    extract_parser.add_argument('--output', help='Output file for extracted data')
    extract_parser.add_argument('--password', help='Password to decrypt data')
    
    # Audio steganography commands
    audio_parser = steg_subparsers.add_parser('audio', help='Audio steganography tools')
    audio_subparsers = audio_parser.add_subparsers(dest='audio_command', help='Audio command')
    
    hide_parser = audio_subparsers.add_parser('hide', help='Hide data in an audio file')
    hide_parser.add_argument('audio', help='Audio file to use')
    hide_parser.add_argument('data', help='Data to hide (text or file path)')
    hide_parser.add_argument('--output', help='Output audio file')
    hide_parser.add_argument('--password', help='Password to encrypt data')
    hide_parser.add_argument('--is-file', action='store_true', help='Treat data as a file path')
    
    extract_parser = audio_subparsers.add_parser('extract', help='Extract data from an audio file')
    extract_parser.add_argument('audio', help='Audio file to extract from')
    extract_parser.add_argument('--output', help='Output file for extracted data')
    extract_parser.add_argument('--password', help='Password to decrypt data')
    
    # Text steganography commands
    text_parser = steg_subparsers.add_parser('text', help='Text steganography tools')
    text_subparsers = text_parser.add_subparsers(dest='text_command', help='Text command')
    
    hide_parser = text_subparsers.add_parser('hide', help='Hide data in text')
    hide_parser.add_argument('text', help='Text file to use')
    hide_parser.add_argument('data', help='Data to hide')
    hide_parser.add_argument('--method', choices=['whitespace', 'unicode', 'zero-width'], default='whitespace', help='Hiding method')
    hide_parser.add_argument('--output', help='Output text file')
    
    extract_parser = text_subparsers.add_parser('extract', help='Extract data from text')
    extract_parser.add_argument('text', help='Text file to extract from')
    extract_parser.add_argument('--method', choices=['whitespace', 'unicode', 'zero-width', 'auto'], default='auto', help='Extraction method')
    extract_parser.add_argument('--output', help='Output file for extracted data')
    
    # Network steganography commands
    network_parser = steg_subparsers.add_parser('network', help='Network steganography tools')
    network_subparsers = network_parser.add_subparsers(dest='network_command', help='Network command')
    
    hide_parser = network_subparsers.add_parser('hide', help='Hide data in network traffic')
    hide_parser.add_argument('--method', choices=['tcp', 'udp', 'icmp', 'dns'], default='tcp', help='Protocol to use')
    hide_parser.add_argument('--target', required=True, help='Target IP or hostname')
    hide_parser.add_argument('--port', type=int, help='Target port (for TCP/UDP)')
    hide_parser.add_argument('--data', required=True, help='Data to hide')
    hide_parser.add_argument('--interface', help='Network interface to use')
    
    listen_parser = network_subparsers.add_parser('listen', help='Listen for hidden data in network traffic')
    listen_parser.add_argument('--method', choices=['tcp', 'udp', 'icmp', 'dns'], default='tcp', help='Protocol to listen for')
    listen_parser.add_argument('--port', type=int, help='Port to listen on (for TCP/UDP)')
    listen_parser.add_argument('--interface', help='Network interface to use')
    listen_parser.add_argument('--timeout', type=int, default=60, help='Timeout in seconds')
    
    # Steganography detection commands
    detect_parser = steg_subparsers.add_parser('detect', help='Steganography detection tools')
    detect_subparsers = detect_parser.add_subparsers(dest='detect_command', help='Detection command')
    
    image_parser = detect_subparsers.add_parser('image', help='Detect steganography in an image')
    image_parser.add_argument('image', help='Image file to analyze')
    
    audio_parser = detect_subparsers.add_parser('audio', help='Detect steganography in an audio file')
    audio_parser.add_argument('audio', help='Audio file to analyze')
    
    text_parser = detect_subparsers.add_parser('text', help='Detect steganography in text')
    text_parser.add_argument('text', help='Text file to analyze')

def setup_crypto_parser(subparsers):
    """Setup the cryptography subcommand parser."""
    crypto_parser = subparsers.add_parser('crypto', help='Cryptography tools')
    crypto_subparsers = crypto_parser.add_subparsers(dest='crypto_command', help='Cryptography command')
    
    # Symmetric encryption commands
    symmetric_parser = crypto_subparsers.add_parser('symmetric', help='Symmetric encryption tools')
    symmetric_subparsers = symmetric_parser.add_subparsers(dest='symmetric_command', help='Symmetric command')
    
    encrypt_parser = symmetric_subparsers.add_parser('encrypt', help='Encrypt data with symmetric encryption')
    encrypt_parser.add_argument('data', help='Data to encrypt (text or file path)')
    encrypt_parser.add_argument('--algorithm', choices=['aes', 'chacha20', 'fernet'], default='aes', help='Encryption algorithm')
    encrypt_parser.add_argument('--key', help='Encryption key (will be generated if not provided)')
    encrypt_parser.add_argument('--output', help='Output file for encrypted data')
    encrypt_parser.add_argument('--is-file', action='store_true', help='Treat data as a file path')
    
    decrypt_parser = symmetric_subparsers.add_parser('decrypt', help='Decrypt data with symmetric encryption')
    decrypt_parser.add_argument('data', help='Data to decrypt (text or file path)')
    decrypt_parser.add_argument('--algorithm', choices=['aes', 'chacha20', 'fernet'], default='aes', help='Decryption algorithm')
    decrypt_parser.add_argument('--key', required=True, help='Decryption key')
    decrypt_parser.add_argument('--output', help='Output file for decrypted data')
    decrypt_parser.add_argument('--is-file', action='store_true', help='Treat data as a file path')
    
    # Asymmetric encryption commands
    asymmetric_parser = crypto_subparsers.add_parser('asymmetric', help='Asymmetric encryption tools')
    asymmetric_subparsers = asymmetric_parser.add_subparsers(dest='asymmetric_command', help='Asymmetric command')
    
    generate_parser = asymmetric_subparsers.add_parser('generate', help='Generate key pair')
    generate_parser.add_argument('--algorithm', choices=['rsa', 'dsa', 'ecc'], default='rsa', help='Key algorithm')
    generate_parser.add_argument('--key-size', type=int, default=2048, help='Key size (for RSA/DSA)')
    generate_parser.add_argument('--curve', choices=['p256', 'p384', 'p521'], default='p256', help='Curve (for ECC)')
    generate_parser.add_argument('--output-private', help='Output file for private key')
    generate_parser.add_argument('--output-public', help='Output file for public key')
    generate_parser.add_argument('--password', help='Password to protect private key')
    
    encrypt_parser = asymmetric_subparsers.add_parser('encrypt', help='Encrypt data with asymmetric encryption')
    encrypt_parser.add_argument('data', help='Data to encrypt (text or file path)')
    encrypt_parser.add_argument('--key', required=True, help='Public key file')
    encrypt_parser.add_argument('--output', help='Output file for encrypted data')
    encrypt_parser.add_argument('--is-file', action='store_true', help='Treat data as a file path')
    
    decrypt_parser = asymmetric_subparsers.add_parser('decrypt', help='Decrypt data with asymmetric encryption')
    decrypt_parser.add_argument('data', help='Data to decrypt (text or file path)')
    decrypt_parser.add_argument('--key', required=True, help='Private key file')
    decrypt_parser.add_argument('--output', help='Output file for decrypted data')
    decrypt_parser.add_argument('--is-file', action='store_true', help='Treat data as a file path')
    decrypt_parser.add_argument('--password', help='Password for private key')
    
    # Hashing commands
    hash_parser = crypto_subparsers.add_parser('hash', help='Hashing tools')
    hash_subparsers = hash_parser.add_subparsers(dest='hash_command', help='Hash command')
    
    calculate_parser = hash_subparsers.add_parser('calculate', help='Calculate hash of data')
    calculate_parser.add_argument('data', help='Data to hash (text or file path)')
    calculate_parser.add_argument('--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'], default='sha256', help='Hash algorithm')
    calculate_parser.add_argument('--is-file', action='store_true', help='Treat data as a file path')
    
    verify_parser = hash_subparsers.add_parser('verify', help='Verify hash of data')
    verify_parser.add_argument('data', help='Data to verify (text or file path)')
    verify_parser.add_argument('hash', help='Expected hash value')
    verify_parser.add_argument('--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'], default='sha256', help='Hash algorithm')
    verify_parser.add_argument('--is-file', action='store_true', help='Treat data as a file path')
    
    # Password commands
    password_parser = crypto_subparsers.add_parser('password', help='Password tools')
    password_subparsers = password_parser.add_subparsers(dest='password_command', help='Password command')
    
    analyze_parser = password_subparsers.add_parser('analyze', help='Analyze password strength')
    analyze_parser.add_argument('password', help='Password to analyze')
    
    generate_parser = password_subparsers.add_parser('generate', help='Generate secure password')
    generate_parser.add_argument('--length', type=int, default=16, help='Password length')
    generate_parser.add_argument('--include-symbols', action='store_true', help='Include symbols')
    generate_parser.add_argument('--include-numbers', action='store_true', help='Include numbers')
    generate_parser.add_argument('--include-uppercase', action='store_true', help='Include uppercase letters')
    generate_parser.add_argument('--include-lowercase', action='store_true', help='Include lowercase letters')
    
    # Digital signature commands
    signature_parser = crypto_subparsers.add_parser('signature', help='Digital signature tools')
    signature_subparsers = signature_parser.add_subparsers(dest='signature_command', help='Signature command')
    
    sign_parser = signature_subparsers.add_parser('sign', help='Sign data')
    sign_parser.add_argument('data', help='Data to sign (text or file path)')
    sign_parser.add_argument('--key', required=True, help='Private key file')
    sign_parser.add_argument('--output', help='Output file for signature')
    sign_parser.add_argument('--is-file', action='store_true', help='Treat data as a file path')
    sign_parser.add_argument('--password', help='Password for private key')
    
    verify_parser = signature_subparsers.add_parser('verify', help='Verify signature')
    verify_parser.add_argument('data', help='Data to verify (text or file path)')
    verify_parser.add_argument('signature', help='Signature file or value')
    verify_parser.add_argument('--key', required=True, help='Public key file')
    verify_parser.add_argument('--is-file', action='store_true', help='Treat data as a file path')
    
    # Key management commands
    key_parser = crypto_subparsers.add_parser('key', help='Key management tools')
    key_subparsers = key_parser.add_subparsers(dest='key_command', help='Key command')
    
    generate_rsa_parser = key_subparsers.add_parser('generate-rsa', help='Generate RSA key pair')
    generate_rsa_parser.add_argument('name', help='Key name')
    generate_rsa_parser.add_argument('--key-size', type=int, default=2048, help='Key size')
    generate_rsa_parser.add_argument('--password', help='Password to protect private key')
    generate_rsa_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing key')
    
    generate_ec_parser = key_subparsers.add_parser('generate-ec', help='Generate EC key pair')
    generate_ec_parser.add_argument('name', help='Key name')
    generate_ec_parser.add_argument('--curve', choices=['secp256r1', 'secp384r1', 'secp521r1'], default='secp256r1', help='Curve')
    generate_ec_parser.add_argument('--password', help='Password to protect private key')
    generate_ec_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing key')
    
    generate_sym_parser = key_subparsers.add_parser('generate-symmetric', help='Generate symmetric key')
    generate_sym_parser.add_argument('name', help='Key name')
    generate_sym_parser.add_argument('--key-size', type=int, default=256, help='Key size')
    generate_sym_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing key')
    
    import_parser = key_subparsers.add_parser('import', help='Import key')
    import_parser.add_argument('name', help='Key name')
    import_parser.add_argument('key_file', help='Key file to import')
    import_parser.add_argument('--key-type', choices=['auto', 'private', 'public', 'certificate', 'symmetric'], default='auto', help='Key type')
    import_parser.add_argument('--password', help='Password for private key')
    import_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing key')
    
    export_parser = key_subparsers.add_parser('export', help='Export key')
    export_parser.add_argument('name', help='Key name')
    export_parser.add_argument('--output', help='Output file')
    export_parser.add_argument('--key-type', choices=['private', 'public', 'certificate', 'symmetric'], default='public', help='Key type')
    export_parser.add_argument('--password', help='Password for private key')
    
    delete_parser = key_subparsers.add_parser('delete', help='Delete key')
    delete_parser.add_argument('name', help='Key name')
    
    list_parser = key_subparsers.add_parser('list', help='List keys')
    
    info_parser = key_subparsers.add_parser('info', help='Get key info')
    info_parser.add_argument('name', help='Key name')
    
    cert_parser = key_subparsers.add_parser('generate-cert', help='Generate self-signed certificate')
    cert_parser.add_argument('name', help='Key name')
    cert_parser.add_argument('subject', help='Certificate subject name')
    cert_parser.add_argument('--valid-days', type=int, default=365, help='Validity period in days')
    cert_parser.add_argument('--key-type', choices=['rsa', 'ec'], default='rsa', help='Key type')
    cert_parser.add_argument('--key-size', type=int, default=2048, help='Key size (for RSA)')
    cert_parser.add_argument('--curve', choices=['secp256r1', 'secp384r1', 'secp521r1'], default='secp256r1', help='Curve (for EC)')
    cert_parser.add_argument('--password', help='Password to protect private key')
    cert_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing key')

def setup_tracking_parser(subparsers):
    """Setup the tracking subcommand parser."""
    tracking_parser = subparsers.add_parser('tracking', help='Tracking and reporting tools')
    tracking_subparsers = tracking_parser.add_subparsers(dest='tracking_command', help='Tracking command')
    
    # Camera commands
    camera_parser = tracking_subparsers.add_parser('camera', help='Camera and forensic tools')
    camera_subparsers = camera_parser.add_subparsers(dest='camera_command', help='Camera command')
    
    capture_parser = camera_subparsers.add_parser('capture', help='Capture image from camera')
    capture_parser.add_argument('--output', help='Output file')
    capture_parser.add_argument('--camera-id', type=int, default=0, help='Camera ID')
    capture_parser.add_argument('--delay', type=int, default=3, help='Delay in seconds')
    
    scan_parser = camera_subparsers.add_parser('scan', help='Scan document')
    scan_parser.add_argument('--output', help='Output file')
    scan_parser.add_argument('--camera-id', type=int, default=0, help='Camera ID')
    scan_parser.add_argument('--extract-text', action='store_true', help='Extract text from document')
    
    analyze_parser = camera_subparsers.add_parser('analyze', help='Analyze image forensically')
    analyze_parser.add_argument('image', help='Image file to analyze')
    analyze_parser.add_argument('--output-dir', help='Output directory for analysis results')
    analyze_parser.add_argument('--metadata', action='store_true', help='Extract metadata')
    analyze_parser.add_argument('--manipulation', action='store_true', help='Detect manipulation')
    analyze_parser.add_argument('--enhance', action='store_true', help='Enhance image')
    
    # Alias tracking commands
    alias_parser = tracking_subparsers.add_parser('alias', help='Alias tracking tools')
    alias_subparsers = alias_parser.add_subparsers(dest='alias_command', help='Alias command')
    
    search_parser = alias_subparsers.add_parser('search', help='Search for aliases')
    search_parser.add_argument('name', help='Name to search for')
    search_parser.add_argument('--state', help='State for property records')
    search_parser.add_argument('--pacer', action='store_true', help='Search PACER records')
    search_parser.add_argument('--property', action='store_true', help='Search property records')
    
    track_parser = alias_subparsers.add_parser('track', help='Track aliases')
    track_parser.add_argument('name', help='Name to track')
    track_parser.add_argument('--add-alias', help='Add alias to tracking')
    track_parser.add_argument('--remove-alias', help='Remove alias from tracking')
    track_parser.add_argument('--list', action='store_true', help='List tracked aliases')
    
    # Report commands
    report_parser = tracking_subparsers.add_parser('report', help='Reporting tools')
    report_subparsers = report_parser.add_subparsers(dest='report_command', help='Report command')
    
    generate_parser = report_subparsers.add_parser('generate', help='Generate report')
    generate_parser.add_argument('subject', help='Subject of report')
    generate_parser.add_argument('--template', choices=['background', 'investigation', 'summary'], default='background', help='Report template')
    generate_parser.add_argument('--output', help='Output file')
    generate_parser.add_argument('--include-osint', action='store_true', help='Include OSINT data')
    generate_parser.add_argument('--include-aliases', action='store_true', help='Include alias data')
    
    evidence_parser = report_subparsers.add_parser('evidence', help='Manage evidence')
    evidence_parser.add_argument('--add', help='Add evidence file')
    evidence_parser.add_argument('--remove', help='Remove evidence file')
    evidence_parser.add_argument('--list', action='store_true', help='List evidence')
    evidence_parser.add_argument('--case', required=True, help='Case name')
    
    # Cross-reference commands
    crossref_parser = tracking_subparsers.add_parser('crossref', help='Cross-reference tools')
    crossref_subparsers = crossref_parser.add_subparsers(dest='crossref_command', help='Cross-reference command')
    
    analyze_parser = crossref_subparsers.add_parser('analyze', help='Analyze connections')
    analyze_parser.add_argument('targets', nargs='+', help='Targets to analyze')
    analyze_parser.add_argument('--output', help='Output file')
    analyze_parser.add_argument('--depth', type=int, default=2, help='Analysis depth')
    
    verify_parser = crossref_subparsers.add_parser('verify', help='Verify identity')
    verify_parser.add_argument('name', help='Name to verify')
    verify_parser.add_argument('--email', help='Email to verify against')
    verify_parser.add_argument('--phone', help='Phone to verify against')
    verify_parser.add_argument('--address', help='Address to verify against')
    
    # Visualization commands
    visualize_parser = tracking_subparsers.add_parser('visualize', help='Visualization tools')
    visualize_subparsers = visualize_parser.add_subparsers(dest='visualize_command', help='Visualization command')
    
    network_parser = visualize_subparsers.add_parser('network', help='Create network graph')
    network_parser.add_argument('data', help='Data file to visualize')
    network_parser.add_argument('--output', help='Output file')
    network_parser.add_argument('--format', choices=['html', 'png', 'pdf'], default='html', help='Output format')
    
    map_parser = visualize_subparsers.add_parser('map', help='Create geographic map')
    map_parser.add_argument('data', help='Data file to visualize')
    map_parser.add_argument('--output', help='Output file')
    map_parser.add_argument('--format', choices=['html', 'png', 'pdf'], default='html', help='Output format')
    
    # Timeline commands
    timeline_parser = tracking_subparsers.add_parser('timeline', help='Timeline tools')
    timeline_subparsers = timeline_parser.add_subparsers(dest='timeline_command', help='Timeline command')
    
    create_parser = timeline_subparsers.add_parser('create', help='Create timeline')
    create_parser.add_argument('--name', required=True, help='Timeline name')
    create_parser.add_argument('--description', help='Timeline description')
    
    add_parser = timeline_subparsers.add_parser('add', help='Add event to timeline')
    add_parser.add_argument('--timeline', required=True, help='Timeline name')
    add_parser.add_argument('--date', required=True, help='Event date (YYYY-MM-DD)')
    add_parser.add_argument('--time', help='Event time (HH:MM:SS)')
    add_parser.add_argument('--description', required=True, help='Event description')
    add_parser.add_argument('--category', help='Event category')
    
    visualize_parser = timeline_subparsers.add_parser('visualize', help='Visualize timeline')
    visualize_parser.add_argument('--timeline', required=True, help='Timeline name')
    visualize_parser.add_argument('--output', help='Output file')
    visualize_parser.add_argument('--format', choices=['html', 'png', 'pdf'], default='html', help='Output format')

def setup_generator_parser(subparsers):
    """Setup the generator subcommand parser."""
    generator_parser = subparsers.add_parser('generate', help='Generator tools')
    generator_subparsers = generator_parser.add_subparsers(dest='generator_command', help='Generator command')
    
    # Username generator commands
    username_parser = generator_subparsers.add_parser('username', help='Username generator')
    username_parser.add_argument('--first-name', help='First name')
    username_parser.add_argument('--last-name', help='Last name')
    username_parser.add_argument('--count', type=int, default=10, help='Number of usernames to generate')
    username_parser.add_argument('--include-numbers', action='store_true', help='Include numbers')
    username_parser.add_argument('--include-special', action='store_true', help='Include special characters')
    username_parser.add_argument('--output', help='Output file')
    
    # Email generator commands
    email_parser = generator_subparsers.add_parser('email', help='Email generator')
    email_parser.add_argument('--first-name', help='First name')
    email_parser.add_argument('--last-name', help='Last name')
    email_parser.add_argument('--domain', help='Email domain')
    email_parser.add_argument('--count', type=int, default=10, help='Number of emails to generate')
    email_parser.add_argument('--output', help='Output file')
    
    # Password generator commands
    password_parser = generator_subparsers.add_parser('password', help='Password generator')
    password_parser.add_argument('--length', type=int, default=16, help='Password length')
    password_parser.add_argument('--count', type=int, default=1, help='Number of passwords to generate')
    password_parser.add_argument('--include-symbols', action='store_true', help='Include symbols')
    password_parser.add_argument('--include-numbers', action='store_true', help='Include numbers')
    password_parser.add_argument('--include-uppercase', action='store_true', help='Include uppercase letters')
    password_parser.add_argument('--include-lowercase', action='store_true', help='Include lowercase letters')
    password_parser.add_argument('--output', help='Output file')
    
    # Identity generator commands
    identity_parser = generator_subparsers.add_parser('identity', help='Identity generator')
    identity_parser.add_argument('--gender', choices=['male', 'female', 'random'], default='random', help='Gender')
    identity_parser.add_argument('--country', default='US', help='Country code')
    identity_parser.add_argument('--age-min', type=int, default=18, help='Minimum age')
    identity_parser.add_argument('--age-max', type=int, default=80, help='Maximum age')
    identity_parser.add_argument('--count', type=int, default=1, help='Number of identities to generate')
    identity_parser.add_argument('--output', help='Output file')
    
    # Document generator commands
    document_parser = generator_subparsers.add_parser('document', help='Document generator')
    document_parser.add_argument('--type', choices=['resume', 'report', 'letter'], required=True, help='Document type')
    document_parser.add_argument('--name', help='Name for document')
    document_parser.add_argument('--template', help='Template file')
    document_parser.add_argument('--output', help='Output file')

def setup_decoder_parser(subparsers):
    """Setup the decoder subcommand parser."""
    decoder_parser = subparsers.add_parser('decode', help='Decoder tools')
    decoder_subparsers = decoder_parser.add_subparsers(dest='decoder_command', help='Decoder command')
    
    # Text decoder commands
    text_parser = decoder_subparsers.add_parser('text', help='Text decoder')
    text_parser.add_argument('data', help='Data to decode')
    text_parser.add_argument('--encoding', choices=['base64', 'hex', 'url', 'html', 'morse', 'binary', 'auto'], default='auto', help='Encoding type')
    text_parser.add_argument('--output', help='Output file')
    
    # File decoder commands
    file_parser = decoder_subparsers.add_parser('file', help='File decoder')
    file_parser.add_argument('file', help='File to decode')
    file_parser.add_argument('--encoding', choices=['base64', 'hex', 'auto'], default='auto', help='Encoding type')
    file_parser.add_argument('--output', help='Output file')
    
    # Binary analyzer commands
    binary_parser = decoder_subparsers.add_parser('binary', help='Binary file analyzer')
    binary_parser.add_argument('file', help='Binary file to analyze')
    binary_parser.add_argument('--output', help='Output file')
    binary_parser.add_argument('--strings', action='store_true', help='Extract strings')
    binary_parser.add_argument('--headers', action='store_true', help='Analyze headers')
    binary_parser.add_argument('--entropy', action='store_true', help='Calculate entropy')

def setup_network_parser(subparsers):
    """Setup the network reconnaissance subcommand parser."""
    network_parser = subparsers.add_parser('network', help='Network reconnaissance tools')
    network_subparsers = network_parser.add_subparsers(dest='network_command', help='Network command')
    
    # Scan commands
    scan_parser = network_subparsers.add_parser('scan', help='Scan host')
    scan_parser.add_argument('target', help='Target to scan (IP, hostname, or CIDR range)')
    scan_parser.add_argument('--scan-type', choices=['basic', 'quick', 'comprehensive', 'stealth', 'vulnerability'], default='basic', help='Scan type')
    scan_parser.add_argument('--output', help='Output file')
    
    # Discovery commands
    discover_parser = network_subparsers.add_parser('discover', help='Discover hosts on network')
    discover_parser.add_argument('network', help='Network to scan (CIDR notation)')
    discover_parser.add_argument('--method', choices=['ping', 'arp', 'syn', 'udp', 'comprehensive'], default='ping', help='Discovery method')
    discover_parser.add_argument('--output', help='Output file')
    
    # Port scan commands
    port_parser = network_subparsers.add_parser('ports', help='Scan ports')
    port_parser.add_argument('target', help='Target to scan (IP or hostname)')
    port_parser.add_argument('--ports', default='common', help='Ports to scan (common, all, well-known, or specific ports like 22,80,443)')
    port_parser.add_argument('--protocol', choices=['tcp', 'udp', 'both'], default='tcp', help='Protocol')
    port_parser.add_argument('--output', help='Output file')
    
    # OS detection commands
    os_parser = network_subparsers.add_parser('os', help='Detect operating system')
    os_parser.add_argument('target', help='Target to scan (IP or hostname)')
    os_parser.add_argument('--output', help='Output file')
    
    # Vulnerability scan commands
    vuln_parser = network_subparsers.add_parser('vulnerability', help='Scan for vulnerabilities')
    vuln_parser.add_argument('target', help='Target to scan (IP or hostname)')
    vuln_parser.add_argument('--output', help='Output file')
    
    # DNS enumeration commands
    dns_parser = network_subparsers.add_parser('dns', help='Enumerate DNS')
    dns_parser.add_argument('domain', help='Domain to enumerate')
    dns_parser.add_argument('--output', help='Output file')
    
    # Packet capture commands
    capture_parser = network_subparsers.add_parser('capture', help='Capture packets')
    capture_parser.add_argument('--interface', required=True, help='Network interface')
    capture_parser.add_argument('--filter', help='Capture filter')
    capture_parser.add_argument('--count', type=int, default=100, help='Packet count')
    capture_parser.add_argument('--output', help='Output file')
    
    # Packet analysis commands
    analyze_parser = network_subparsers.add_parser('analyze', help='Analyze packet capture')
    analyze_parser.add_argument('file', help='PCAP file to analyze')
    
    # Traceroute commands
    trace_parser = network_subparsers.add_parser('trace', help='Trace route to target')
    trace_parser.add_argument('target', help='Target to trace (IP or hostname)')
    trace_parser.add_argument('--max-hops', type=int, default=30, help='Maximum hops')

def main():
    """Main entry point for the CLI."""
    # Create the argument parser
    parser = argparse.ArgumentParser(description='Ultimate PI Tool - Combining OSINT, Steganography, Cryptography, and more')
    parser.add_argument('--version', action='version', version='Ultimate PI Tool v1.0.0')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    # Create subparsers for each component
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Setup component parsers
    setup_osint_parser(subparsers)
    setup_steg_parser(subparsers)
    setup_crypto_parser(subparsers)
    setup_tracking_parser(subparsers)
    setup_generator_parser(subparsers)
    setup_decoder_parser(subparsers)
    setup_network_parser(subparsers)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Print banner
    print_banner()
    
    # Check if a command was provided
    if not args.command:
        parser.print_help()
        return
    
    # Handle commands
    try:
        if args.command == 'osint':
            handle_osint_command(args)
        elif args.command == 'steg':
            handle_steg_command(args)
        elif args.command == 'crypto':
            handle_crypto_command(args)
        elif args.command == 'tracking':
            handle_tracking_command(args)
        elif args.command == 'generate':
            handle_generator_command(args)
        elif args.command == 'decode':
            handle_decoder_command(args)
        elif args.command == 'network':
            handle_network_command(args)
        else:
            console.print(f"[bold red]Unknown command:[/] {args.command}")
            parser.print_help()
    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        return 1
    
    return 0

def handle_osint_command(args):
    """Handle OSINT commands."""
    if not args.osint_command:
        console.print("[bold red]Error:[/] No OSINT command specified")
        return
    
    if args.osint_command == 'linkedin':
        handle_linkedin_command(args)
    elif args.osint_command == 'twitter':
        handle_twitter_command(args)
    elif args.osint_command == 'email':
        handle_email_command(args)
    elif args.osint_command == 'domain':
        handle_domain_command(args)
    elif args.osint_command == 'username':
        handle_username_command(args)
    elif args.osint_command == 'breach':
        handle_breach_command(args)
    else:
        console.print(f"[bold red]Unknown OSINT command:[/] {args.osint_command}")

def handle_linkedin_command(args):
    """Handle LinkedIn commands."""
    if not args.linkedin_command:
        console.print("[bold red]Error:[/] No LinkedIn command specified")
        return
    
    if args.linkedin_command == 'profile':
        console.print(f"[bold blue]Getting LinkedIn profile for:[/] {args.username}")
        result = linkedin.get_profile(args.username)
        display_result(result)
    elif args.linkedin_command == 'search':
        console.print(f"[bold blue]Searching LinkedIn for:[/] {args.keywords}")
        result = linkedin.search_people(
            args.keywords,
            first_name=args.first_name,
            last_name=args.last_name,
            school=args.school,
            title=args.title,
            company=args.company
        )
        display_result(result)
    else:
        console.print(f"[bold red]Unknown LinkedIn command:[/] {args.linkedin_command}")

def handle_twitter_command(args):
    """Handle Twitter commands."""
    if not args.twitter_command:
        console.print("[bold red]Error:[/] No Twitter command specified")
        return
    
    if args.twitter_command == 'profile':
        console.print(f"[bold blue]Getting Twitter profile for:[/] {args.username}")
        result = twitter.get_profile(args.username)
        display_result(result)
    elif args.twitter_command == 'search':
        console.print(f"[bold blue]Searching Twitter for:[/] {args.query}")
        result = twitter.search_tweets(args.query, count=args.count, search_type=args.type)
        display_result(result)
    elif args.twitter_command == 'tweets':
        console.print(f"[bold blue]Getting tweets from:[/] {args.username}")
        result = twitter.get_user_tweets(args.username, count=args.count)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown Twitter command:[/] {args.twitter_command}")

def handle_email_command(args):
    """Handle email commands."""
    if not args.email_command:
        console.print("[bold red]Error:[/] No email command specified")
        return
    
    if args.email_command == 'validate':
        console.print(f"[bold blue]Validating email:[/] {args.email}")
        result = email.validate_email(args.email)
        display_result(result)
    elif args.email_command == 'reputation':
        console.print(f"[bold blue]Checking email reputation:[/] {args.email}")
        result = email.check_reputation(args.email)
        display_result(result)
    elif args.email_command == 'breach':
        console.print(f"[bold blue]Checking email for breaches:[/] {args.email}")
        result = email.check_breaches(args.email)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown email command:[/] {args.email_command}")

def handle_domain_command(args):
    """Handle domain commands."""
    if not args.domain_command:
        console.print("[bold red]Error:[/] No domain command specified")
        return
    
    if args.domain_command == 'whois':
        console.print(f"[bold blue]Getting WHOIS information for:[/] {args.domain}")
        result = domain.get_whois(args.domain)
        display_result(result)
    elif args.domain_command == 'dns':
        console.print(f"[bold blue]Getting DNS records for:[/] {args.domain}")
        result = domain.get_dns_records(args.domain, record_type=args.record_type)
        display_result(result)
    elif args.domain_command == 'ip':
        console.print(f"[bold blue]Getting IP information for:[/] {args.domain}")
        result = domain.get_ip_info(args.domain)
        display_result(result)
    elif args.domain_command == 'breach':
        console.print(f"[bold blue]Checking domain for breaches:[/] {args.domain}")
        result = domain.check_breaches(args.domain)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown domain command:[/] {args.domain_command}")

def handle_username_command(args):
    """Handle username commands."""
    if not args.username_command:
        console.print("[bold red]Error:[/] No username command specified")
        return
    
    if args.username_command == 'search':
        console.print(f"[bold blue]Searching for username:[/] {args.username}")
        result = username.search_username(args.username)
        display_result(result)
    elif args.username_command == 'variations':
        console.print(f"[bold blue]Generating username variations for:[/] {args.username}")
        result = username.generate_variations(args.username)
        display_result(result)
    elif args.username_command == 'breach':
        console.print(f"[bold blue]Checking username for breaches:[/] {args.username}")
        result = username.check_breaches(args.username)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown username command:[/] {args.username_command}")

def handle_breach_command(args):
    """Handle breach commands."""
    if not args.breach_command:
        console.print("[bold red]Error:[/] No breach command specified")
        return
    
    if args.breach_command == 'check':
        console.print(f"[bold blue]Checking for breaches:[/] {args.target}")
        result = breaches.check_breaches(args.target, target_type=args.type)
        display_result(result)
    elif args.breach_command == 'list':
        console.print("[bold blue]Listing known breaches[/]")
        result = breaches.list_breaches(count=args.count)
        display_result(result)
    elif args.breach_command == 'details':
        console.print(f"[bold blue]Getting details for breach:[/] {args.breach_name}")
        result = breaches.get_breach_details(args.breach_name)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown breach command:[/] {args.breach_command}")

def handle_steg_command(args):
    """Handle steganography commands."""
    if not args.steg_command:
        console.print("[bold red]Error:[/] No steganography command specified")
        return
    
    if args.steg_command == 'image':
        handle_image_steg_command(args)
    elif args.steg_command == 'audio':
        handle_audio_steg_command(args)
    elif args.steg_command == 'text':
        handle_text_steg_command(args)
    elif args.steg_command == 'network':
        handle_network_steg_command(args)
    elif args.steg_command == 'detect':
        handle_detect_steg_command(args)
    else:
        console.print(f"[bold red]Unknown steganography command:[/] {args.steg_command}")

def handle_image_steg_command(args):
    """Handle image steganography commands."""
    if not args.image_command:
        console.print("[bold red]Error:[/] No image steganography command specified")
        return
    
    if args.image_command == 'hide':
        console.print(f"[bold blue]Hiding data in image:[/] {args.image}")
        if args.is_file:
            result = image.hide_file_in_image(args.image, args.data, output_file=args.output, password=args.password)
        else:
            result = image.hide_text_in_image(args.image, args.data, output_file=args.output, password=args.password)
        display_result(result)
    elif args.image_command == 'extract':
        console.print(f"[bold blue]Extracting data from image:[/] {args.image}")
        result = image.extract_from_image(args.image, output_file=args.output, password=args.password)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown image steganography command:[/] {args.image_command}")

def handle_audio_steg_command(args):
    """Handle audio steganography commands."""
    if not args.audio_command:
        console.print("[bold red]Error:[/] No audio steganography command specified")
        return
    
    if args.audio_command == 'hide':
        console.print(f"[bold blue]Hiding data in audio:[/] {args.audio}")
        if args.is_file:
            result = audio.hide_file_in_audio(args.audio, args.data, output_file=args.output, password=args.password)
        else:
            result = audio.hide_text_in_audio(args.audio, args.data, output_file=args.output, password=args.password)
        display_result(result)
    elif args.audio_command == 'extract':
        console.print(f"[bold blue]Extracting data from audio:[/] {args.audio}")
        result = audio.extract_from_audio(args.audio, output_file=args.output, password=args.password)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown audio steganography command:[/] {args.audio_command}")

def handle_text_steg_command(args):
    """Handle text steganography commands."""
    if not args.text_command:
        console.print("[bold red]Error:[/] No text steganography command specified")
        return
    
    if args.text_command == 'hide':
        console.print(f"[bold blue]Hiding data in text:[/] {args.text}")
        result = text.hide_in_text(args.text, args.data, method=args.method, output_file=args.output)
        display_result(result)
    elif args.text_command == 'extract':
        console.print(f"[bold blue]Extracting data from text:[/] {args.text}")
        result = text.extract_from_text(args.text, method=args.method, output_file=args.output)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown text steganography command:[/] {args.text_command}")

def handle_network_steg_command(args):
    """Handle network steganography commands."""
    if not args.network_command:
        console.print("[bold red]Error:[/] No network steganography command specified")
        return
    
    if args.network_command == 'hide':
        console.print(f"[bold blue]Hiding data in network traffic to:[/] {args.target}")
        result = network.hide_in_traffic(args.method, args.target, args.data, port=args.port, interface=args.interface)
        display_result(result)
    elif args.network_command == 'listen':
        console.print(f"[bold blue]Listening for hidden data in network traffic[/]")
        result = network.listen_for_data(args.method, port=args.port, interface=args.interface, timeout=args.timeout)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown network steganography command:[/] {args.network_command}")

def handle_detect_steg_command(args):
    """Handle steganography detection commands."""
    if not args.detect_command:
        console.print("[bold red]Error:[/] No steganography detection command specified")
        return
    
    if args.detect_command == 'image':
        console.print(f"[bold blue]Detecting steganography in image:[/] {args.image}")
        result = detector.detect_in_image(args.image)
        display_result(result)
    elif args.detect_command == 'audio':
        console.print(f"[bold blue]Detecting steganography in audio:[/] {args.audio}")
        result = detector.detect_in_audio(args.audio)
        display_result(result)
    elif args.detect_command == 'text':
        console.print(f"[bold blue]Detecting steganography in text:[/] {args.text}")
        result = detector.detect_in_text(args.text)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown steganography detection command:[/] {args.detect_command}")

def handle_crypto_command(args):
    """Handle cryptography commands."""
    if not args.crypto_command:
        console.print("[bold red]Error:[/] No cryptography command specified")
        return
    
    if args.crypto_command == 'symmetric':
        handle_symmetric_command(args)
    elif args.crypto_command == 'asymmetric':
        handle_asymmetric_command(args)
    elif args.crypto_command == 'hash':
        handle_hash_command(args)
    elif args.crypto_command == 'password':
        handle_password_command(args)
    elif args.crypto_command == 'signature':
        handle_signature_command(args)
    elif args.crypto_command == 'key':
        handle_key_command(args)
    else:
        console.print(f"[bold red]Unknown cryptography command:[/] {args.crypto_command}")

def handle_symmetric_command(args):
    """Handle symmetric encryption commands."""
    if not args.symmetric_command:
        console.print("[bold red]Error:[/] No symmetric encryption command specified")
        return
    
    if args.symmetric_command == 'encrypt':
        console.print("[bold blue]Encrypting data with symmetric encryption[/]")
        if args.is_file:
            result = symmetric.encrypt_file(args.data, algorithm=args.algorithm, key=args.key, output_file=args.output)
        else:
            result = symmetric.encrypt_text(args.data, algorithm=args.algorithm, key=args.key, output_file=args.output)
        display_result(result)
    elif args.symmetric_command == 'decrypt':
        console.print("[bold blue]Decrypting data with symmetric encryption[/]")
        if args.is_file:
            result = symmetric.decrypt_file(args.data, algorithm=args.algorithm, key=args.key, output_file=args.output)
        else:
            result = symmetric.decrypt_text(args.data, algorithm=args.algorithm, key=args.key, output_file=args.output)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown symmetric encryption command:[/] {args.symmetric_command}")

def handle_asymmetric_command(args):
    """Handle asymmetric encryption commands."""
    if not args.asymmetric_command:
        console.print("[bold red]Error:[/] No asymmetric encryption command specified")
        return
    
    if args.asymmetric_command == 'generate':
        console.print("[bold blue]Generating asymmetric key pair[/]")
        result = asymmetric.generate_key_pair(
            algorithm=args.algorithm,
            key_size=args.key_size,
            curve=args.curve,
            output_private=args.output_private,
            output_public=args.output_public,
            password=args.password
        )
        display_result(result)
    elif args.asymmetric_command == 'encrypt':
        console.print("[bold blue]Encrypting data with asymmetric encryption[/]")
        if args.is_file:
            result = asymmetric.encrypt_file(args.data, args.key, output_file=args.output)
        else:
            result = asymmetric.encrypt_text(args.data, args.key, output_file=args.output)
        display_result(result)
    elif args.asymmetric_command == 'decrypt':
        console.print("[bold blue]Decrypting data with asymmetric encryption[/]")
        if args.is_file:
            result = asymmetric.decrypt_file(args.data, args.key, output_file=args.output, password=args.password)
        else:
            result = asymmetric.decrypt_text(args.data, args.key, output_file=args.output, password=args.password)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown asymmetric encryption command:[/] {args.asymmetric_command}")

def handle_hash_command(args):
    """Handle hash commands."""
    if not args.hash_command:
        console.print("[bold red]Error:[/] No hash command specified")
        return
    
    if args.hash_command == 'calculate':
        console.print("[bold blue]Calculating hash[/]")
        if args.is_file:
            result = hashing.hash_file(args.data, algorithm=args.algorithm)
        else:
            result = hashing.hash_text(args.data, algorithm=args.algorithm)
        display_result(result)
    elif args.hash_command == 'verify':
        console.print("[bold blue]Verifying hash[/]")
        if args.is_file:
            result = hashing.verify_file_hash(args.data, args.hash, algorithm=args.algorithm)
        else:
            result = hashing.verify_text_hash(args.data, args.hash, algorithm=args.algorithm)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown hash command:[/] {args.hash_command}")

def handle_password_command(args):
    """Handle password commands."""
    if not args.password_command:
        console.print("[bold red]Error:[/] No password command specified")
        return
    
    if args.password_command == 'analyze':
        console.print(f"[bold blue]Analyzing password strength:[/] {args.password}")
        result = password.analyze_strength(args.password)
        display_result(result)
    elif args.password_command == 'generate':
        console.print("[bold blue]Generating secure password[/]")
        result = password.generate_password(
            length=args.length,
            include_symbols=args.include_symbols,
            include_numbers=args.include_numbers,
            include_uppercase=args.include_uppercase,
            include_lowercase=args.include_lowercase
        )
        display_result(result)
    else:
        console.print(f"[bold red]Unknown password command:[/] {args.password_command}")

def handle_signature_command(args):
    """Handle digital signature commands."""
    if not args.signature_command:
        console.print("[bold red]Error:[/] No signature command specified")
        return
    
    if args.signature_command == 'sign':
        console.print("[bold blue]Signing data[/]")
        if args.is_file:
            result = signatures.sign_file(args.data, args.key, output_file=args.output, password=args.password)
        else:
            result = signatures.sign_text(args.data, args.key, output_file=args.output, password=args.password)
        display_result(result)
    elif args.signature_command == 'verify':
        console.print("[bold blue]Verifying signature[/]")
        if args.is_file:
            result = signatures.verify_file(args.data, args.signature, args.key)
        else:
            result = signatures.verify_text(args.data, args.signature, args.key)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown signature command:[/] {args.signature_command}")

def handle_key_command(args):
    """Handle key management commands."""
    if not args.key_command:
        console.print("[bold red]Error:[/] No key command specified")
        return
    
    # Create key manager
    key_manager = keys.KeyManager()
    
    if args.key_command == 'generate-rsa':
        console.print(f"[bold blue]Generating RSA key pair:[/] {args.name}")
        result = key_manager.generate_rsa_key_pair(
            args.name,
            key_size=args.key_size,
            password=args.password,
            overwrite=args.overwrite
        )
        display_result(result)
    elif args.key_command == 'generate-ec':
        console.print(f"[bold blue]Generating EC key pair:[/] {args.name}")
        result = key_manager.generate_ec_key_pair(
            args.name,
            curve=args.curve,
            password=args.password,
            overwrite=args.overwrite
        )
        display_result(result)
    elif args.key_command == 'generate-symmetric':
        console.print(f"[bold blue]Generating symmetric key:[/] {args.name}")
        result = key_manager.generate_symmetric_key(
            args.name,
            key_size=args.key_size,
            overwrite=args.overwrite
        )
        display_result(result)
    elif args.key_command == 'import':
        console.print(f"[bold blue]Importing key:[/] {args.name}")
        result = key_manager.import_key(
            args.name,
            args.key_file,
            key_type=args.key_type,
            password=args.password,
            overwrite=args.overwrite
        )
        display_result(result)
    elif args.key_command == 'export':
        console.print(f"[bold blue]Exporting key:[/] {args.name}")
        result = key_manager.export_key(
            args.name,
            output_file=args.output,
            key_type=args.key_type,
            password=args.password
        )
        display_result(result)
    elif args.key_command == 'delete':
        console.print(f"[bold blue]Deleting key:[/] {args.name}")
        result = key_manager.delete_key(args.name)
        display_result(result)
    elif args.key_command == 'list':
        console.print("[bold blue]Listing keys[/]")
        result = key_manager.list_keys()
        display_result(result)
    elif args.key_command == 'info':
        console.print(f"[bold blue]Getting key info:[/] {args.name}")
        result = key_manager.get_key_info(args.name)
        display_result(result)
    elif args.key_command == 'generate-cert':
        console.print(f"[bold blue]Generating self-signed certificate:[/] {args.name}")
        result = key_manager.generate_certificate(
            args.name,
            args.subject,
            valid_days=args.valid_days,
            key_type=args.key_type,
            key_size=args.key_size,
            curve=args.curve,
            password=args.password,
            overwrite=args.overwrite
        )
        display_result(result)
    else:
        console.print(f"[bold red]Unknown key command:[/] {args.key_command}")

def handle_tracking_command(args):
    """Handle tracking commands."""
    if not args.tracking_command:
        console.print("[bold red]Error:[/] No tracking command specified")
        return
    
    if args.tracking_command == 'camera':
        handle_camera_command(args)
    elif args.tracking_command == 'alias':
        handle_alias_command(args)
    elif args.tracking_command == 'report':
        handle_report_command(args)
    elif args.tracking_command == 'crossref':
        handle_crossref_command(args)
    elif args.tracking_command == 'visualize':
        handle_visualize_command(args)
    elif args.tracking_command == 'timeline':
        handle_timeline_command(args)
    else:
        console.print(f"[bold red]Unknown tracking command:[/] {args.tracking_command}")

def handle_camera_command(args):
    """Handle camera commands."""
    if not args.camera_command:
        console.print("[bold red]Error:[/] No camera command specified")
        return
    
    if args.camera_command == 'capture':
        console.print("[bold blue]Capturing image from camera[/]")
        result = camera.capture_image(output_file=args.output, camera_id=args.camera_id, delay=args.delay)
        display_result(result)
    elif args.camera_command == 'scan':
        console.print("[bold blue]Scanning document[/]")
        result = camera.scan_document(output_file=args.output, camera_id=args.camera_id, extract_text=args.extract_text)
        display_result(result)
    elif args.camera_command == 'analyze':
        console.print(f"[bold blue]Analyzing image forensically:[/] {args.image}")
        result = camera.analyze_image(
            args.image,
            output_dir=args.output_dir,
            extract_metadata=args.metadata,
            detect_manipulation=args.manipulation,
            enhance_image=args.enhance
        )
        display_result(result)
    else:
        console.print(f"[bold red]Unknown camera command:[/] {args.camera_command}")

def handle_alias_command(args):
    """Handle alias commands."""
    if not args.alias_command:
        console.print("[bold red]Error:[/] No alias command specified")
        return
    
    if args.alias_command == 'search':
        console.print(f"[bold blue]Searching for aliases:[/] {args.name}")
        result = alias.search_aliases(
            args.name,
            state=args.state,
            search_pacer=args.pacer,
            search_property=args.property
        )
        display_result(result)
    elif args.alias_command == 'track':
        console.print(f"[bold blue]Tracking aliases for:[/] {args.name}")
        if args.add_alias:
            result = alias.add_alias(args.name, args.add_alias)
        elif args.remove_alias:
            result = alias.remove_alias(args.name, args.remove_alias)
        elif args.list:
            result = alias.list_aliases(args.name)
        else:
            result = alias.get_tracking_status(args.name)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown alias command:[/] {args.alias_command}")

def handle_report_command(args):
    """Handle report commands."""
    if not args.report_command:
        console.print("[bold red]Error:[/] No report command specified")
        return
    
    if args.report_command == 'generate':
        console.print(f"[bold blue]Generating report for:[/] {args.subject}")
        result = reports.generate_report(
            args.subject,
            template=args.template,
            output_file=args.output,
            include_osint=args.include_osint,
            include_aliases=args.include_aliases
        )
        display_result(result)
    elif args.report_command == 'evidence':
        console.print(f"[bold blue]Managing evidence for case:[/] {args.case}")
        if args.add:
            result = reports.add_evidence(args.case, args.add)
        elif args.remove:
            result = reports.remove_evidence(args.case, args.remove)
        elif args.list:
            result = reports.list_evidence(args.case)
        else:
            console.print("[bold red]Error:[/] No evidence action specified")
            return
        display_result(result)
    else:
        console.print(f"[bold red]Unknown report command:[/] {args.report_command}")

def handle_crossref_command(args):
    """Handle cross-reference commands."""
    if not args.crossref_command:
        console.print("[bold red]Error:[/] No cross-reference command specified")
        return
    
    if args.crossref_command == 'analyze':
        console.print("[bold blue]Analyzing connections between targets[/]")
        result = crossref.analyze_connections(args.targets, output_file=args.output, depth=args.depth)
        display_result(result)
    elif args.crossref_command == 'verify':
        console.print(f"[bold blue]Verifying identity:[/] {args.name}")
        result = crossref.verify_identity(
            args.name,
            email=args.email,
            phone=args.phone,
            address=args.address
        )
        display_result(result)
    else:
        console.print(f"[bold red]Unknown cross-reference command:[/] {args.crossref_command}")

def handle_visualize_command(args):
    """Handle visualization commands."""
    if not args.visualize_command:
        console.print("[bold red]Error:[/] No visualization command specified")
        return
    
    if args.visualize_command == 'network':
        console.print(f"[bold blue]Creating network graph from:[/] {args.data}")
        result = visualize.create_network_graph(args.data, output_file=args.output, output_format=args.format)
        display_result(result)
    elif args.visualize_command == 'map':
        console.print(f"[bold blue]Creating geographic map from:[/] {args.data}")
        result = visualize.create_geographic_map(args.data, output_file=args.output, output_format=args.format)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown visualization command:[/] {args.visualize_command}")

def handle_timeline_command(args):
    """Handle timeline commands."""
    if not args.timeline_command:
        console.print("[bold red]Error:[/] No timeline command specified")
        return
    
    if args.timeline_command == 'create':
        console.print(f"[bold blue]Creating timeline:[/] {args.name}")
        result = timeline.create_timeline(args.name, description=args.description)
        display_result(result)
    elif args.timeline_command == 'add':
        console.print(f"[bold blue]Adding event to timeline:[/] {args.timeline}")
        result = timeline.add_event(
            args.timeline,
            args.date,
            args.description,
            time=args.time,
            category=args.category
        )
        display_result(result)
    elif args.timeline_command == 'visualize':
        console.print(f"[bold blue]Visualizing timeline:[/] {args.timeline}")
        result = timeline.visualize_timeline(args.timeline, output_file=args.output, output_format=args.format)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown timeline command:[/] {args.timeline_command}")

def handle_generator_command(args):
    """Handle generator commands."""
    if not args.generator_command:
        console.print("[bold red]Error:[/] No generator command specified")
        return
    
    if args.generator_command == 'username':
        console.print("[bold blue]Generating usernames[/]")
        result = username_gen.generate_usernames(
            first_name=args.first_name,
            last_name=args.last_name,
            count=args.count,
            include_numbers=args.include_numbers,
            include_special=args.include_special,
            output_file=args.output
        )
        display_result(result)
    elif args.generator_command == 'email':
        console.print("[bold blue]Generating email addresses[/]")
        result = email_gen.generate_emails(
            first_name=args.first_name,
            last_name=args.last_name,
            domain=args.domain,
            count=args.count,
            output_file=args.output
        )
        display_result(result)
    elif args.generator_command == 'password':
        console.print("[bold blue]Generating passwords[/]")
        result = password_gen.generate_passwords(
            length=args.length,
            count=args.count,
            include_symbols=args.include_symbols,
            include_numbers=args.include_numbers,
            include_uppercase=args.include_uppercase,
            include_lowercase=args.include_lowercase,
            output_file=args.output
        )
        display_result(result)
    elif args.generator_command == 'identity':
        console.print("[bold blue]Generating identities[/]")
        result = identity.generate_identities(
            gender=args.gender,
            country=args.country,
            age_min=args.age_min,
            age_max=args.age_max,
            count=args.count,
            output_file=args.output
        )
        display_result(result)
    elif args.generator_command == 'document':
        console.print(f"[bold blue]Generating {args.type} document[/]")
        result = document.generate_document(
            doc_type=args.type,
            name=args.name,
            template=args.template,
            output_file=args.output
        )
        display_result(result)
    else:
        console.print(f"[bold red]Unknown generator command:[/] {args.generator_command}")

def handle_decoder_command(args):
    """Handle decoder commands."""
    if not args.decoder_command:
        console.print("[bold red]Error:[/] No decoder command specified")
        return
    
    if args.decoder_command == 'text':
        console.print("[bold blue]Decoding text[/]")
        result = decoders.decode_text(args.data, encoding=args.encoding, output_file=args.output)
        display_result(result)
    elif args.decoder_command == 'file':
        console.print(f"[bold blue]Decoding file:[/] {args.file}")
        result = decoders.decode_file(args.file, encoding=args.encoding, output_file=args.output)
        display_result(result)
    elif args.decoder_command == 'binary':
        console.print(f"[bold blue]Analyzing binary file:[/] {args.file}")
        result = decoders.analyze_binary(
            args.file,
            output_file=args.output,
            extract_strings=args.strings,
            analyze_headers=args.headers,
            calculate_entropy=args.entropy
        )
        display_result(result)
    else:
        console.print(f"[bold red]Unknown decoder command:[/] {args.decoder_command}")

def handle_network_command(args):
    """Handle network reconnaissance commands."""
    if not args.network_command:
        console.print("[bold red]Error:[/] No network command specified")
        return
    
    # Create network reconnaissance object
    net_recon = NetworkRecon()
    
    if args.network_command == 'scan':
        console.print(f"[bold blue]Scanning host:[/] {args.target}")
        result = net_recon.scan_host(args.target, scan_type=args.scan_type, output_file=args.output)
        display_result(result)
    elif args.network_command == 'discover':
        console.print(f"[bold blue]Discovering hosts on network:[/] {args.network}")
        result = net_recon.discover_network(args.network, method=args.method, output_file=args.output)
        display_result(result)
    elif args.network_command == 'ports':
        console.print(f"[bold blue]Scanning ports on:[/] {args.target}")
        result = net_recon.scan_ports(args.target, ports=args.ports, protocol=args.protocol, output_file=args.output)
        display_result(result)
    elif args.network_command == 'os':
        console.print(f"[bold blue]Detecting operating system on:[/] {args.target}")
        result = net_recon.os_detection(args.target, output_file=args.output)
        display_result(result)
    elif args.network_command == 'vulnerability':
        console.print(f"[bold blue]Scanning for vulnerabilities on:[/] {args.target}")
        result = net_recon.vulnerability_scan(args.target, output_file=args.output)
        display_result(result)
    elif args.network_command == 'dns':
        console.print(f"[bold blue]Enumerating DNS for domain:[/] {args.domain}")
        result = net_recon.dns_enumeration(args.domain, output_file=args.output)
        display_result(result)
    elif args.network_command == 'capture':
        console.print(f"[bold blue]Capturing packets on interface:[/] {args.interface}")
        result = net_recon.capture_packets(args.interface, filter=args.filter, count=args.count, output_file=args.output)
        display_result(result)
    elif args.network_command == 'analyze':
        console.print(f"[bold blue]Analyzing packet capture:[/] {args.file}")
        result = net_recon.analyze_pcap(args.file)
        display_result(result)
    elif args.network_command == 'trace':
        console.print(f"[bold blue]Tracing route to:[/] {args.target}")
        result = net_recon.trace_route(args.target, max_hops=args.max_hops)
        display_result(result)
    else:
        console.print(f"[bold red]Unknown network command:[/] {args.network_command}")

def display_result(result):
    """Display the result of a command."""
    if result is None:
        console.print("[bold red]Error:[/] Command failed")
        return
    
    if isinstance(result, bool):
        if result:
            console.print("[bold green]Success![/]")
        else:
            console.print("[bold red]Failed![/]")
        return
    
    if isinstance(result, str):
        console.print(f"[bold green]Result:[/] {result}")
        return
    
    if isinstance(result, (list, tuple)):
        console.print("[bold green]Results:[/]")
        for item in result:
            console.print(f"- {item}")
        return
    
    if isinstance(result, dict):
        console.print("[bold green]Result:[/]")
        for key, value in result.items():
            console.print(f"[bold]{key}:[/] {value}")
        return
    
    # Fallback
    console.print(f"[bold green]Result:[/] {result}")

if __name__ == "__main__":
    sys.exit(main())
