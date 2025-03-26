#!/usr/bin/env python3
"""
Test script for the Ultimate PI Tool components.
This script tests key functionality of each component.
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Create test results directory
TEST_RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_results')
os.makedirs(TEST_RESULTS_DIR, exist_ok=True)

def test_osint_components():
    """Test OSINT components."""
    logger.info("Testing OSINT components...")
    results = {}
    
    try:
        # Import OSINT components
        from pi_tool.osint import linkedin, twitter, email, domain, username, breaches
        
        # Test email validation
        test_email = "test@example.com"
        logger.info(f"Testing email validation for: {test_email}")
        email_result = email.validate_email(test_email)
        results['email_validation'] = {
            'input': test_email,
            'result': email_result,
            'status': 'success' if email_result else 'failure'
        }
        
        # Test domain WHOIS
        test_domain = "example.com"
        logger.info(f"Testing domain WHOIS for: {test_domain}")
        domain_result = domain.get_whois(test_domain)
        results['domain_whois'] = {
            'input': test_domain,
            'result': str(domain_result)[:100] + "..." if domain_result and len(str(domain_result)) > 100 else domain_result,
            'status': 'success' if domain_result else 'failure'
        }
        
        # Test username variations
        test_username = "johndoe"
        logger.info(f"Testing username variations for: {test_username}")
        username_result = username.generate_variations(test_username)
        results['username_variations'] = {
            'input': test_username,
            'result': username_result[:5] if username_result and len(username_result) > 5 else username_result,
            'status': 'success' if username_result else 'failure'
        }
        
    except Exception as e:
        logger.error(f"Error testing OSINT components: {str(e)}")
        results['error'] = str(e)
    
    return results

def test_steganography_components():
    """Test steganography components."""
    logger.info("Testing steganography components...")
    results = {}
    
    try:
        # Import steganography components
        from pi_tool.steganography import image, audio, text, network, detector
        
        # Create test files directory
        test_files_dir = os.path.join(TEST_RESULTS_DIR, 'steg_test_files')
        os.makedirs(test_files_dir, exist_ok=True)
        
        # Test text steganography
        test_text = "This is a test message for steganography."
        secret_data = "SECRET_DATA_123"
        logger.info("Testing text steganography")
        
        # Create a test text file
        text_file = os.path.join(test_files_dir, 'test_text.txt')
        with open(text_file, 'w') as f:
            f.write(test_text)
        
        # Hide data in text
        output_text_file = os.path.join(test_files_dir, 'steg_text.txt')
        hide_result = text.hide_in_text(text_file, secret_data, method='whitespace', output_file=output_text_file)
        
        # Extract data from text
        extract_result = text.extract_from_text(output_text_file, method='whitespace')
        
        results['text_steganography'] = {
            'input_text': test_text,
            'secret_data': secret_data,
            'extracted_data': extract_result,
            'status': 'success' if extract_result == secret_data else 'failure'
        }
        
    except Exception as e:
        logger.error(f"Error testing steganography components: {str(e)}")
        results['error'] = str(e)
    
    return results

def test_cryptography_components():
    """Test cryptography components."""
    logger.info("Testing cryptography components...")
    results = {}
    
    try:
        # Import cryptography components
        from pi_tool.cryptography import symmetric, asymmetric, hashing, password, signatures, keys
        
        # Test hashing
        test_data = "This is a test message for hashing."
        logger.info("Testing hashing functions")
        
        # Calculate hash
        hash_result = hashing.hash_text(test_data, algorithm='sha256')
        
        # Verify hash
        verify_result = hashing.verify_text_hash(test_data, hash_result, algorithm='sha256')
        
        results['hashing'] = {
            'input_data': test_data,
            'hash_result': hash_result,
            'verification': verify_result,
            'status': 'success' if verify_result else 'failure'
        }
        
        # Test password strength analyzer
        test_password = "P@ssw0rd123!"
        logger.info(f"Testing password strength analyzer for: {test_password}")
        password_result = password.analyze_strength(test_password)
        
        results['password_analysis'] = {
            'input_password': test_password,
            'analysis_result': password_result,
            'status': 'success' if password_result else 'failure'
        }
        
        # Test symmetric encryption
        test_data = "This is a test message for encryption."
        test_key = "testkey123"
        logger.info("Testing symmetric encryption")
        
        # Create test files directory
        test_files_dir = os.path.join(TEST_RESULTS_DIR, 'crypto_test_files')
        os.makedirs(test_files_dir, exist_ok=True)
        
        # Encrypt data
        encrypted_file = os.path.join(test_files_dir, 'encrypted.bin')
        encrypt_result = symmetric.encrypt_text(test_data, algorithm='aes', key=test_key, output_file=encrypted_file)
        
        # Decrypt data
        decrypted_file = os.path.join(test_files_dir, 'decrypted.txt')
        decrypt_result = symmetric.decrypt_text(encrypted_file, algorithm='aes', key=test_key, output_file=decrypted_file)
        
        # Read decrypted data
        with open(decrypted_file, 'r') as f:
            decrypted_data = f.read()
        
        results['symmetric_encryption'] = {
            'input_data': test_data,
            'decrypted_data': decrypted_data,
            'status': 'success' if decrypted_data == test_data else 'failure'
        }
        
    except Exception as e:
        logger.error(f"Error testing cryptography components: {str(e)}")
        results['error'] = str(e)
    
    return results

def test_tracking_components():
    """Test tracking components."""
    logger.info("Testing tracking components...")
    results = {}
    
    try:
        # Import tracking components
        from pi_tool.tracking import reports, crossref, visualize, timeline
        
        # Test timeline creation
        timeline_name = "test_timeline"
        logger.info(f"Testing timeline creation: {timeline_name}")
        
        # Create timeline
        create_result = timeline.create_timeline(timeline_name, description="Test timeline for testing")
        
        # Add events to timeline
        event1_result = timeline.add_event(
            timeline_name,
            "2025-03-25",
            "First test event",
            time="10:00:00",
            category="Test"
        )
        
        event2_result = timeline.add_event(
            timeline_name,
            "2025-03-26",
            "Second test event",
            time="11:00:00",
            category="Test"
        )
        
        # Create test files directory
        test_files_dir = os.path.join(TEST_RESULTS_DIR, 'tracking_test_files')
        os.makedirs(test_files_dir, exist_ok=True)
        
        # Visualize timeline
        output_file = os.path.join(test_files_dir, 'timeline.html')
        visualize_result = timeline.visualize_timeline(timeline_name, output_file=output_file)
        
        results['timeline'] = {
            'timeline_name': timeline_name,
            'creation_result': create_result,
            'event1_result': event1_result,
            'event2_result': event2_result,
            'visualization_result': visualize_result,
            'status': 'success' if create_result and event1_result and event2_result and visualize_result else 'failure'
        }
        
    except Exception as e:
        logger.error(f"Error testing tracking components: {str(e)}")
        results['error'] = str(e)
    
    return results

def test_generator_components():
    """Test generator components."""
    logger.info("Testing generator components...")
    results = {}
    
    try:
        # Import generator components
        from pi_tool.generators import username as username_gen
        from pi_tool.generators import email as email_gen
        from pi_tool.generators import password as password_gen
        
        # Test username generator
        first_name = "John"
        last_name = "Doe"
        logger.info(f"Testing username generator for: {first_name} {last_name}")
        
        # Generate usernames
        username_result = username_gen.generate_usernames(
            first_name=first_name,
            last_name=last_name,
            count=5,
            include_numbers=True
        )
        
        results['username_generator'] = {
            'first_name': first_name,
            'last_name': last_name,
            'generated_usernames': username_result,
            'status': 'success' if username_result and len(username_result) > 0 else 'failure'
        }
        
        # Test email generator
        logger.info(f"Testing email generator for: {first_name} {last_name}")
        
        # Generate emails
        email_result = email_gen.generate_emails(
            first_name=first_name,
            last_name=last_name,
            domain="example.com",
            count=5
        )
        
        results['email_generator'] = {
            'first_name': first_name,
            'last_name': last_name,
            'domain': "example.com",
            'generated_emails': email_result,
            'status': 'success' if email_result and len(email_result) > 0 else 'failure'
        }
        
        # Test password generator
        logger.info("Testing password generator")
        
        # Generate password
        password_result = password_gen.generate_passwords(
            length=12,
            count=3,
            include_symbols=True,
            include_numbers=True,
            include_uppercase=True,
            include_lowercase=True
        )
        
        results['password_generator'] = {
            'length': 12,
            'generated_passwords': password_result,
            'status': 'success' if password_result and len(password_result) > 0 else 'failure'
        }
        
    except Exception as e:
        logger.error(f"Error testing generator components: {str(e)}")
        results['error'] = str(e)
    
    return results

def test_decoder_components():
    """Test decoder components."""
    logger.info("Testing decoder components...")
    results = {}
    
    try:
        # Import decoder components
        from pi_tool.decoders import decoders
        
        # Test base64 decoding
        base64_data = "SGVsbG8gV29ybGQh"  # "Hello World!" in base64
        logger.info(f"Testing base64 decoding: {base64_data}")
        
        # Decode base64
        decode_result = decoders.decode_text(base64_data, encoding='base64')
        
        results['base64_decoding'] = {
            'input_data': base64_data,
            'decoded_data': decode_result,
            'expected_data': "Hello World!",
            'status': 'success' if decode_result == "Hello World!" else 'failure'
        }
        
        # Test hex decoding
        hex_data = "48656c6c6f20576f726c6421"  # "Hello World!" in hex
        logger.info(f"Testing hex decoding: {hex_data}")
        
        # Decode hex
        decode_result = decoders.decode_text(hex_data, encoding='hex')
        
        results['hex_decoding'] = {
            'input_data': hex_data,
            'decoded_data': decode_result,
            'expected_data': "Hello World!",
            'status': 'success' if decode_result == "Hello World!" else 'failure'
        }
        
    except Exception as e:
        logger.error(f"Error testing decoder components: {str(e)}")
        results['error'] = str(e)
    
    return results

def test_network_components():
    """Test network components."""
    logger.info("Testing network components...")
    results = {}
    
    try:
        # Import network components
        from pi_tool.network import NetworkRecon
        
        # Create network reconnaissance object
        net_recon = NetworkRecon()
        
        # Test DNS enumeration
        test_domain = "example.com"
        logger.info(f"Testing DNS enumeration for: {test_domain}")
        
        # Create test files directory
        test_files_dir = os.path.join(TEST_RESULTS_DIR, 'network_test_files')
        os.makedirs(test_files_dir, exist_ok=True)
        
        # Enumerate DNS
        output_file = os.path.join(test_files_dir, 'dns_enumeration.json')
        dns_result = net_recon.dns_enumeration(test_domain, output_file=output_file)
        
        results['dns_enumeration'] = {
            'domain': test_domain,
            'result': str(dns_result)[:100] + "..." if dns_result and len(str(dns_result)) > 100 else dns_result,
            'status': 'success' if dns_result else 'failure'
        }
        
        # Test traceroute
        test_target = "example.com"
        logger.info(f"Testing traceroute to: {test_target}")
        
        # Trace route
        trace_result = net_recon.trace_route(test_target, max_hops=5)
        
        results['traceroute'] = {
            'target': test_target,
            'result': str(trace_result)[:100] + "..." if trace_result and len(str(trace_result)) > 100 else trace_result,
            'status': 'success' if trace_result else 'failure'
        }
        
    except Exception as e:
        logger.error(f"Error testing network components: {str(e)}")
        results['error'] = str(e)
    
    return results

def run_all_tests():
    """Run all component tests."""
    logger.info("Running all component tests...")
    
    # Create timestamp for test run
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    
    # Run tests
    test_results = {
        'timestamp': timestamp,
        'osint': test_osint_components(),
        'steganography': test_steganography_components(),
        'cryptography': test_cryptography_components(),
        'tracking': test_tracking_components(),
        'generators': test_generator_components(),
        'decoders': test_decoder_components(),
        'network': test_network_components()
    }
    
    # Save test results
    results_file = os.path.join(TEST_RESULTS_DIR, f'test_results_{timestamp}.json')
    with open(results_file, 'w') as f:
        json.dump(test_results, f, indent=4)
    
    logger.info(f"Test results saved to: {results_file}")
    
    # Print summary
    print("\n=== TEST SUMMARY ===")
    for component, results in test_results.items():
        if component == 'timestamp':
            continue
        
        success_count = 0
        failure_count = 0
        error = None
        
        if 'error' in results:
            error = results['error']
        else:
            for test, test_result in results.items():
                if isinstance(test_result, dict) and 'status' in test_result:
                    if test_result['status'] == 'success':
                        success_count += 1
                    else:
                        failure_count += 1
        
        if error:
            print(f"{component.upper()}: ERROR - {error}")
        else:
            print(f"{component.upper()}: {success_count} passed, {failure_count} failed")
    
    return test_results

def main():
    """Main entry point for the test script."""
    parser = argparse.ArgumentParser(description='Ultimate PI Tool - Component Tests')
    parser.add_argument('--component', choices=['osint', 'steganography', 'cryptography', 'tracking', 'generators', 'decoders', 'network', 'all'], default='all', help='Component to test')
    
    args = parser.parse_args()
    
    if args.component == 'all':
        run_all_tests()
    elif args.component == 'osint':
        test_osint_components()
    elif args.component == 'steganography':
        test_steganography_components()
    elif args.component == 'cryptography':
        test_cryptography_components()
    elif args.component == 'tracking':
        test_tracking_components()
    elif args.component == 'generators':
        test_generator_components()
    elif args.component == 'decoders':
        test_decoder_components()
    elif args.component == 'network':
        test_network_components()

if __name__ == '__main__':
    main()
