"""
Cryptography module for the Ultimate PI Tool.

This module provides functionality for encryption, decryption, hashing,
password analysis, and digital signatures.
"""

from .symmetric import SymmetricCrypto
from .asymmetric import AsymmetricCrypto
from .hashing import HashingFunctions
from .password import PasswordAnalyzer
from .signatures import DigitalSignatures

def handle_crypto_command(args):
    """Handle cryptography command line arguments and dispatch to appropriate handler."""
    if args.crypto_command == "symmetric":
        symmetric = SymmetricCrypto()
        if args.encrypt:
            if not args.input or not args.output:
                print("Please provide both input and output files.")
                return
            symmetric.encrypt_file(args.input, args.output, args.password, args.algorithm)
        elif args.decrypt:
            if not args.input or not args.output:
                print("Please provide both input and output files.")
                return
            symmetric.decrypt_file(args.input, args.output, args.password, args.algorithm)
        else:
            print("Please specify either --encrypt or --decrypt operation.")
    
    elif args.crypto_command == "asymmetric":
        asymmetric = AsymmetricCrypto()
        if args.generate_keys:
            asymmetric.generate_key_pair(args.key_size, args.private_key, args.public_key)
        elif args.encrypt:
            if not args.input or not args.output or not args.public_key:
                print("Please provide input, output, and public key files.")
                return
            asymmetric.encrypt_file(args.input, args.output, args.public_key)
        elif args.decrypt:
            if not args.input or not args.output or not args.private_key:
                print("Please provide input, output, and private key files.")
                return
            asymmetric.decrypt_file(args.input, args.output, args.private_key)
        else:
            print("Please specify operation: --generate-keys, --encrypt, or --decrypt.")
    
    elif args.crypto_command == "hash":
        hashing = HashingFunctions()
        if args.file:
            hashing.hash_file(args.file, args.algorithm)
        elif args.text:
            hashing.hash_text(args.text, args.algorithm)
        else:
            print("Please provide either --file or --text to hash.")
    
    elif args.crypto_command == "password":
        password = PasswordAnalyzer()
        if args.analyze:
            password.analyze_strength(args.password)
        elif args.generate:
            password.generate_password(args.length, args.complexity)
        else:
            print("Please specify either --analyze or --generate operation.")
    
    elif args.crypto_command == "signature":
        signatures = DigitalSignatures()
        if args.sign:
            if not args.input or not args.signature or not args.private_key:
                print("Please provide input, signature, and private key files.")
                return
            signatures.sign_file(args.input, args.signature, args.private_key)
        elif args.verify:
            if not args.input or not args.signature or not args.public_key:
                print("Please provide input, signature, and public key files.")
                return
            signatures.verify_file(args.input, args.signature, args.public_key)
        else:
            print("Please specify either --sign or --verify operation.")
    
    else:
        print(f"Unknown cryptography command: {args.crypto_command}")
