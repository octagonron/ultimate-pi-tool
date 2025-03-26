# Ultimate PI Tool

A comprehensive private investigation tool combining OSINT, steganography, cryptography, tracking, and more.

## Overview

The Ultimate PI Tool is a powerful, all-in-one solution for private investigators, security researchers, and digital forensics professionals. It combines multiple capabilities into a single unified interface:

- **OSINT (Open Source Intelligence)**: Gather information from social media, email, domains, and more
- **Steganography**: Hide and extract data in images, audio, text, and network traffic
- **Cryptography**: Encrypt/decrypt data, manage keys, create/verify signatures
- **Tracking & Reporting**: Camera with forensic capabilities, alias tracking, cross-referencing
- **Generators**: Create usernames, emails, passwords, identities, and documents
- **Decoders**: Decode various encoding schemes and analyze binary files
- **Network Reconnaissance**: Scan networks, discover hosts, analyze packets

## Features

### OSINT Components

- LinkedIn profile retrieval and people search
- Twitter profile retrieval, tweet search, and user tweet collection
- Email validation, reputation checking, and breach information lookup
- Domain WHOIS, DNS records, IP resolution, and breach checking
- Username social media profile discovery and breach checking
- Comprehensive breach checking for emails, usernames, domains, and IP addresses

### Steganography Components

- Image steganography (LSB method)
- Audio steganography
- Text steganography (whitespace, Unicode, zero-width characters)
- Network steganography (TCP, UDP, ICMP, DNS)
- Steganography detection tools

### Cryptography Components

- Symmetric encryption/decryption (AES, ChaCha20, Fernet)
- Asymmetric encryption/decryption (RSA)
- Hashing functions (SHA-256, SHA-512, MD5, etc.)
- Password strength analyzer and generator
- Digital signature creation and verification
- Key management system (public/private keys)

### Tracking Components

- Camera function with forensic capabilities
- Alias tracking with PACER and property records integration
- Background report generation
- Cross-reference functionality
- Visualization tools for connections
- Timeline analysis

### Generator Components

- Username generator
- Email generator
- Password generator
- Identity generator
- Document generator

### Decoder Components

- Text decoder (Base64, Hex, URL, HTML, Morse, Binary)
- File decoder
- Binary file analyzer

### Network Reconnaissance Module

- Host scanning
- Network discovery
- Port scanning
- OS detection
- Vulnerability scanning
- DNS enumeration
- Packet capture and analysis
- Traceroute

## Installation

### Prerequisites

- Python 3.8+
- Required Python packages (see requirements.txt)

### Setup

1. Clone the repository:
```
git clone https://github.com/yourusername/ultimate-pi-tool.git
cd ultimate-pi-tool
```

2. Install dependencies:
```
pip install -r requirements.txt
```

## Usage

The Ultimate PI Tool provides both a command-line interface (CLI) and a web-based graphical user interface (GUI).

### Command-Line Interface

Run the CLI with:

```
python cli.py [command] [subcommand] [options]
```

For example:

```
# OSINT - Get LinkedIn profile
python cli.py osint linkedin profile johndoe

# Steganography - Hide data in image
python cli.py steg image hide --image path/to/image.jpg --data "Secret message" --output hidden.png

# Cryptography - Generate key pair
python cli.py crypto asymmetric generate --algorithm rsa --key-size 2048 --output-private private.pem --output-public public.pem
```

For help on available commands:

```
python cli.py --help
```

### Web-Based GUI

Start the web interface with:

```
python web_gui.py
```

Then open your browser and navigate to:

```
http://localhost:5000
```

## Project Structure

```
pi_tool/
├── pi_tool/
│   ├── osint/
│   │   ├── __init__.py
│   │   ├── linkedin.py
│   │   ├── twitter.py
│   │   ├── email.py
│   │   ├── domain.py
│   │   ├── username.py
│   │   └── breaches.py
│   ├── steganography/
│   │   ├── __init__.py
│   │   ├── image.py
│   │   ├── audio.py
│   │   ├── text.py
│   │   ├── network.py
│   │   └── detector.py
│   ├── cryptography/
│   │   ├── __init__.py
│   │   ├── symmetric.py
│   │   ├── asymmetric.py
│   │   ├── hashing.py
│   │   ├── password.py
│   │   ├── signatures.py
│   │   └── keys.py
│   ├── tracking/
│   │   ├── __init__.py
│   │   ├── camera.py
│   │   ├── alias.py
│   │   ├── reports.py
│   │   ├── crossref.py
│   │   ├── visualize.py
│   │   └── timeline.py
│   ├── generators/
│   │   ├── __init__.py
│   │   ├── username.py
│   │   ├── email.py
│   │   ├── password.py
│   │   ├── identity.py
│   │   └── document.py
│   ├── decoders/
│   │   ├── __init__.py
│   │   └── decoders.py
│   └── network/
│       ├── __init__.py
│       └── network_recon.py
├── cli.py
├── web_gui.py
├── requirements.txt
└── README.md
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for legitimate security research, digital forensics, and private investigation purposes only. Users are responsible for complying with applicable laws and regulations when using this tool.
