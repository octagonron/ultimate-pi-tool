#!/usr/bin/env python3
"""
Ultimate PI Tool - Web-based GUI Interface

This is the main entry point for the web-based GUI interface of the Ultimate PI Tool.
It provides access to all components through a user-friendly web interface.
"""

import os
import sys
import json
import logging
import argparse
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from werkzeug.utils import secure_filename
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

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
    logger.error(f"Error importing components: {str(e)}")
    logger.error("Make sure you're running from the project root directory.")
    sys.exit(1)

# Create Flask app
app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
app.secret_key = os.urandom(24)

# Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
RESULTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'wav', 'mp3', 'pcap'}

# Create folders if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULTS_FOLDER'] = RESULTS_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Render the main dashboard."""
    return render_template('index.html')

# OSINT Routes
@app.route('/osint')
def osint_dashboard():
    """Render the OSINT dashboard."""
    return render_template('osint/dashboard.html')

@app.route('/osint/linkedin', methods=['GET', 'POST'])
def osint_linkedin():
    """Handle LinkedIn OSINT requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'profile':
            username = request.form.get('username')
            if username:
                result = linkedin.get_profile(username)
        elif action == 'search':
            keywords = request.form.get('keywords')
            if keywords:
                result = linkedin.search_people(
                    keywords,
                    first_name=request.form.get('first_name'),
                    last_name=request.form.get('last_name'),
                    school=request.form.get('school'),
                    title=request.form.get('title'),
                    company=request.form.get('company')
                )
        
        return render_template('osint/linkedin.html', result=result)
    
    return render_template('osint/linkedin.html')

@app.route('/osint/twitter', methods=['GET', 'POST'])
def osint_twitter():
    """Handle Twitter OSINT requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'profile':
            username = request.form.get('username')
            if username:
                result = twitter.get_profile(username)
        elif action == 'search':
            query = request.form.get('query')
            if query:
                count = int(request.form.get('count', 20))
                search_type = request.form.get('type', 'Top')
                result = twitter.search_tweets(query, count=count, search_type=search_type)
        elif action == 'tweets':
            username = request.form.get('username')
            if username:
                count = int(request.form.get('count', 20))
                result = twitter.get_user_tweets(username, count=count)
        
        return render_template('osint/twitter.html', result=result)
    
    return render_template('osint/twitter.html')

@app.route('/osint/email', methods=['GET', 'POST'])
def osint_email():
    """Handle email OSINT requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'validate':
            email_address = request.form.get('email')
            if email_address:
                result = email.validate_email(email_address)
        elif action == 'reputation':
            email_address = request.form.get('email')
            if email_address:
                result = email.check_reputation(email_address)
        elif action == 'breach':
            email_address = request.form.get('email')
            if email_address:
                result = email.check_breaches(email_address)
        
        return render_template('osint/email.html', result=result)
    
    return render_template('osint/email.html')

@app.route('/osint/domain', methods=['GET', 'POST'])
def osint_domain():
    """Handle domain OSINT requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'whois':
            domain_name = request.form.get('domain')
            if domain_name:
                result = domain.get_whois(domain_name)
        elif action == 'dns':
            domain_name = request.form.get('domain')
            if domain_name:
                record_type = request.form.get('record_type', 'ALL')
                result = domain.get_dns_records(domain_name, record_type=record_type)
        elif action == 'ip':
            domain_name = request.form.get('domain')
            if domain_name:
                result = domain.get_ip_info(domain_name)
        elif action == 'breach':
            domain_name = request.form.get('domain')
            if domain_name:
                result = domain.check_breaches(domain_name)
        
        return render_template('osint/domain.html', result=result)
    
    return render_template('osint/domain.html')

@app.route('/osint/username', methods=['GET', 'POST'])
def osint_username():
    """Handle username OSINT requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'search':
            username_value = request.form.get('username')
            if username_value:
                result = username.search_username(username_value)
        elif action == 'variations':
            username_value = request.form.get('username')
            if username_value:
                result = username.generate_variations(username_value)
        elif action == 'breach':
            username_value = request.form.get('username')
            if username_value:
                result = username.check_breaches(username_value)
        
        return render_template('osint/username.html', result=result)
    
    return render_template('osint/username.html')

@app.route('/osint/breach', methods=['GET', 'POST'])
def osint_breach():
    """Handle breach OSINT requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'check':
            target = request.form.get('target')
            if target:
                target_type = request.form.get('type')
                result = breaches.check_breaches(target, target_type=target_type)
        elif action == 'list':
            count = int(request.form.get('count', 10))
            result = breaches.list_breaches(count=count)
        elif action == 'details':
            breach_name = request.form.get('breach_name')
            if breach_name:
                result = breaches.get_breach_details(breach_name)
        
        return render_template('osint/breach.html', result=result)
    
    return render_template('osint/breach.html')

# Steganography Routes
@app.route('/steg')
def steg_dashboard():
    """Render the steganography dashboard."""
    return render_template('steg/dashboard.html')

@app.route('/steg/image', methods=['GET', 'POST'])
def steg_image():
    """Handle image steganography requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'hide':
            # Check if image file was uploaded
            if 'image' not in request.files:
                return render_template('steg/image.html', error="No image file provided")
            
            image_file = request.files['image']
            if image_file.filename == '':
                return render_template('steg/image.html', error="No image file selected")
            
            if image_file and allowed_file(image_file.filename):
                # Save the uploaded image
                image_filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                image_file.save(image_path)
                
                # Get data to hide
                data = request.form.get('data')
                is_file = 'data_file' in request.files and request.files['data_file'].filename != ''
                
                if is_file:
                    data_file = request.files['data_file']
                    data_filename = secure_filename(data_file.filename)
                    data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
                    data_file.save(data_path)
                    data = data_path
                
                # Get password if provided
                password = request.form.get('password')
                
                # Generate output filename
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                output_filename = f"steg_image_{timestamp}.png"
                output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
                
                # Hide data in image
                if is_file:
                    result = image.hide_file_in_image(image_path, data, output_file=output_path, password=password)
                else:
                    result = image.hide_text_in_image(image_path, data, output_file=output_path, password=password)
                
                if result:
                    return render_template('steg/image.html', result=result, output_file=output_filename)
            else:
                return render_template('steg/image.html', error="Invalid file type")
        
        elif action == 'extract':
            # Check if image file was uploaded
            if 'image' not in request.files:
                return render_template('steg/image.html', error="No image file provided")
            
            image_file = request.files['image']
            if image_file.filename == '':
                return render_template('steg/image.html', error="No image file selected")
            
            if image_file and allowed_file(image_file.filename):
                # Save the uploaded image
                image_filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                image_file.save(image_path)
                
                # Get password if provided
                password = request.form.get('password')
                
                # Generate output filename
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                output_filename = f"extracted_{timestamp}.txt"
                output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
                
                # Extract data from image
                result = image.extract_from_image(image_path, output_file=output_path, password=password)
                
                if result:
                    return render_template('steg/image.html', result=result, output_file=output_filename)
            else:
                return render_template('steg/image.html', error="Invalid file type")
    
    return render_template('steg/image.html')

@app.route('/steg/audio', methods=['GET', 'POST'])
def steg_audio():
    """Handle audio steganography requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'hide':
            # Check if audio file was uploaded
            if 'audio' not in request.files:
                return render_template('steg/audio.html', error="No audio file provided")
            
            audio_file = request.files['audio']
            if audio_file.filename == '':
                return render_template('steg/audio.html', error="No audio file selected")
            
            if audio_file and allowed_file(audio_file.filename):
                # Save the uploaded audio
                audio_filename = secure_filename(audio_file.filename)
                audio_path = os.path.join(app.config['UPLOAD_FOLDER'], audio_filename)
                audio_file.save(audio_path)
                
                # Get data to hide
                data = request.form.get('data')
                is_file = 'data_file' in request.files and request.files['data_file'].filename != ''
                
                if is_file:
                    data_file = request.files['data_file']
                    data_filename = secure_filename(data_file.filename)
                    data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
                    data_file.save(data_path)
                    data = data_path
                
                # Get password if provided
                password = request.form.get('password')
                
                # Generate output filename
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                output_filename = f"steg_audio_{timestamp}.wav"
                output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
                
                # Hide data in audio
                if is_file:
                    result = audio.hide_file_in_audio(audio_path, data, output_file=output_path, password=password)
                else:
                    result = audio.hide_text_in_audio(audio_path, data, output_file=output_path, password=password)
                
                if result:
                    return render_template('steg/audio.html', result=result, output_file=output_filename)
            else:
                return render_template('steg/audio.html', error="Invalid file type")
        
        elif action == 'extract':
            # Check if audio file was uploaded
            if 'audio' not in request.files:
                return render_template('steg/audio.html', error="No audio file provided")
            
            audio_file = request.files['audio']
            if audio_file.filename == '':
                return render_template('steg/audio.html', error="No audio file selected")
            
            if audio_file and allowed_file(audio_file.filename):
                # Save the uploaded audio
                audio_filename = secure_filename(audio_file.filename)
                audio_path = os.path.join(app.config['UPLOAD_FOLDER'], audio_filename)
                audio_file.save(audio_path)
                
                # Get password if provided
                password = request.form.get('password')
                
                # Generate output filename
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                output_filename = f"extracted_{timestamp}.txt"
                output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
                
                # Extract data from audio
                result = audio.extract_from_audio(audio_path, output_file=output_path, password=password)
                
                if result:
                    return render_template('steg/audio.html', result=result, output_file=output_filename)
            else:
                return render_template('steg/audio.html', error="Invalid file type")
    
    return render_template('steg/audio.html')

@app.route('/steg/text', methods=['GET', 'POST'])
def steg_text():
    """Handle text steganography requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'hide':
            # Get text to use
            text = request.form.get('text')
            text_file = None
            
            if 'text_file' in request.files:
                text_file = request.files['text_file']
            
            if (not text or text.strip() == '') and (not text_file or text_file.filename == ''):
                return render_template('steg/text.html', error="No text provided")
            
            # If text file was uploaded, use that instead of text input
            if text_file and text_file.filename != '':
                text_filename = secure_filename(text_file.filename)
                text_path = os.path.join(app.config['UPLOAD_FOLDER'], text_filename)
                text_file.save(text_path)
                
                with open(text_path, 'r', encoding='utf-8') as f:
                    text = f.read()
            
            # Get data to hide
            data = request.form.get('data')
            if not data or data.strip() == '':
                return render_template('steg/text.html', error="No data provided to hide")
            
            # Get method
            method = request.form.get('method', 'whitespace')
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"steg_text_{timestamp}.txt"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Hide data in text
            result = text.hide_in_text(text, data, method=method, output_file=output_path)
            
            if result:
                return render_template('steg/text.html', result=result, output_file=output_filename)
        
        elif action == 'extract':
            # Get text to extract from
            text = request.form.get('text')
            text_file = None
            
            if 'text_file' in request.files:
                text_file = request.files['text_file']
            
            if (not text or text.strip() == '') and (not text_file or text_file.filename == ''):
                return render_template('steg/text.html', error="No text provided")
            
            # If text file was uploaded, use that instead of text input
            if text_file and text_file.filename != '':
                text_filename = secure_filename(text_file.filename)
                text_path = os.path.join(app.config['UPLOAD_FOLDER'], text_filename)
                text_file.save(text_path)
                
                with open(text_path, 'r', encoding='utf-8') as f:
                    text = f.read()
            
            # Get method
            method = request.form.get('method', 'auto')
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"extracted_{timestamp}.txt"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Extract data from text
            result = text.extract_from_text(text, method=method, output_file=output_path)
            
            if result:
                return render_template('steg/text.html', result=result, output_file=output_filename)
    
    return render_template('steg/text.html')

@app.route('/steg/network', methods=['GET', 'POST'])
def steg_network():
    """Handle network steganography requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'hide':
            # Get parameters
            method = request.form.get('method', 'tcp')
            target = request.form.get('target')
            port = request.form.get('port')
            data = request.form.get('data')
            interface = request.form.get('interface')
            
            if not target:
                return render_template('steg/network.html', error="No target provided")
            
            if not data:
                return render_template('steg/network.html', error="No data provided to hide")
            
            if port:
                port = int(port)
            
            # Hide data in network traffic
            result = network.hide_in_traffic(method, target, data, port=port, interface=interface)
            
            return render_template('steg/network.html', result=result)
        
        elif action == 'listen':
            # Get parameters
            method = request.form.get('method', 'tcp')
            port = request.form.get('port')
            interface = request.form.get('interface')
            timeout = request.form.get('timeout', 60)
            
            if port:
                port = int(port)
            
            if timeout:
                timeout = int(timeout)
            
            # Listen for hidden data in network traffic
            result = network.listen_for_data(method, port=port, interface=interface, timeout=timeout)
            
            return render_template('steg/network.html', result=result)
    
    return render_template('steg/network.html')

@app.route('/steg/detect', methods=['GET', 'POST'])
def steg_detect():
    """Handle steganography detection requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'image':
            # Check if image file was uploaded
            if 'image' not in request.files:
                return render_template('steg/detect.html', error="No image file provided")
            
            image_file = request.files['image']
            if image_file.filename == '':
                return render_template('steg/detect.html', error="No image file selected")
            
            if image_file and allowed_file(image_file.filename):
                # Save the uploaded image
                image_filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                image_file.save(image_path)
                
                # Detect steganography in image
                result = detector.detect_in_image(image_path)
                
                return render_template('steg/detect.html', result=result)
            else:
                return render_template('steg/detect.html', error="Invalid file type")
        
        elif action == 'audio':
            # Check if audio file was uploaded
            if 'audio' not in request.files:
                return render_template('steg/detect.html', error="No audio file provided")
            
            audio_file = request.files['audio']
            if audio_file.filename == '':
                return render_template('steg/detect.html', error="No audio file selected")
            
            if audio_file and allowed_file(audio_file.filename):
                # Save the uploaded audio
                audio_filename = secure_filename(audio_file.filename)
                audio_path = os.path.join(app.config['UPLOAD_FOLDER'], audio_filename)
                audio_file.save(audio_path)
                
                # Detect steganography in audio
                result = detector.detect_in_audio(audio_path)
                
                return render_template('steg/detect.html', result=result)
            else:
                return render_template('steg/detect.html', error="Invalid file type")
        
        elif action == 'text':
            # Get text to analyze
            text = request.form.get('text')
            text_file = None
            
            if 'text_file' in request.files:
                text_file = request.files['text_file']
            
            if (not text or text.strip() == '') and (not text_file or text_file.filename == ''):
                return render_template('steg/detect.html', error="No text provided")
            
            # If text file was uploaded, use that instead of text input
            if text_file and text_file.filename != '':
                text_filename = secure_filename(text_file.filename)
                text_path = os.path.join(app.config['UPLOAD_FOLDER'], text_filename)
                text_file.save(text_path)
                
                with open(text_path, 'r', encoding='utf-8') as f:
                    text = f.read()
            
            # Detect steganography in text
            result = detector.detect_in_text(text)
            
            return render_template('steg/detect.html', result=result)
    
    return render_template('steg/detect.html')

# Cryptography Routes
@app.route('/crypto')
def crypto_dashboard():
    """Render the cryptography dashboard."""
    return render_template('crypto/dashboard.html')

@app.route('/crypto/symmetric', methods=['GET', 'POST'])
def crypto_symmetric():
    """Handle symmetric encryption requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'encrypt':
            # Get data to encrypt
            data = request.form.get('data')
            data_file = None
            
            if 'data_file' in request.files:
                data_file = request.files['data_file']
            
            if (not data or data.strip() == '') and (not data_file or data_file.filename == ''):
                return render_template('crypto/symmetric.html', error="No data provided")
            
            # If data file was uploaded, use that instead of text input
            is_file = False
            if data_file and data_file.filename != '':
                data_filename = secure_filename(data_file.filename)
                data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
                data_file.save(data_path)
                data = data_path
                is_file = True
            
            # Get parameters
            algorithm = request.form.get('algorithm', 'aes')
            key = request.form.get('key')
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"encrypted_{timestamp}.bin"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Encrypt data
            if is_file:
                result = symmetric.encrypt_file(data, algorithm=algorithm, key=key, output_file=output_path)
            else:
                result = symmetric.encrypt_text(data, algorithm=algorithm, key=key, output_file=output_path)
            
            if result:
                return render_template('crypto/symmetric.html', result=result, output_file=output_filename)
        
        elif action == 'decrypt':
            # Check if data file was uploaded
            if 'data' not in request.files:
                return render_template('crypto/symmetric.html', error="No data file provided")
            
            data_file = request.files['data']
            if data_file.filename == '':
                return render_template('crypto/symmetric.html', error="No data file selected")
            
            # Save the uploaded data
            data_filename = secure_filename(data_file.filename)
            data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
            data_file.save(data_path)
            
            # Get parameters
            algorithm = request.form.get('algorithm', 'aes')
            key = request.form.get('key')
            
            if not key:
                return render_template('crypto/symmetric.html', error="No key provided")
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"decrypted_{timestamp}.txt"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Decrypt data
            is_file = request.form.get('is_file') == 'true'
            if is_file:
                result = symmetric.decrypt_file(data_path, algorithm=algorithm, key=key, output_file=output_path)
            else:
                result = symmetric.decrypt_text(data_path, algorithm=algorithm, key=key, output_file=output_path)
            
            if result:
                return render_template('crypto/symmetric.html', result=result, output_file=output_filename)
    
    return render_template('crypto/symmetric.html')

@app.route('/crypto/asymmetric', methods=['GET', 'POST'])
def crypto_asymmetric():
    """Handle asymmetric encryption requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'generate':
            # Get parameters
            algorithm = request.form.get('algorithm', 'rsa')
            key_size = request.form.get('key_size', 2048)
            curve = request.form.get('curve', 'p256')
            password = request.form.get('password')
            
            if key_size:
                key_size = int(key_size)
            
            # Generate output filenames
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            private_filename = f"private_key_{timestamp}.pem"
            public_filename = f"public_key_{timestamp}.pem"
            private_path = os.path.join(app.config['RESULTS_FOLDER'], private_filename)
            public_path = os.path.join(app.config['RESULTS_FOLDER'], public_filename)
            
            # Generate key pair
            result = asymmetric.generate_key_pair(
                algorithm=algorithm,
                key_size=key_size,
                curve=curve,
                output_private=private_path,
                output_public=public_path,
                password=password
            )
            
            if result:
                return render_template('crypto/asymmetric.html', result=result, private_file=private_filename, public_file=public_filename)
        
        elif action == 'encrypt':
            # Get data to encrypt
            data = request.form.get('data')
            data_file = None
            
            if 'data_file' in request.files:
                data_file = request.files['data_file']
            
            if (not data or data.strip() == '') and (not data_file or data_file.filename == ''):
                return render_template('crypto/asymmetric.html', error="No data provided")
            
            # If data file was uploaded, use that instead of text input
            is_file = False
            if data_file and data_file.filename != '':
                data_filename = secure_filename(data_file.filename)
                data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
                data_file.save(data_path)
                data = data_path
                is_file = True
            
            # Check if key file was uploaded
            if 'key' not in request.files:
                return render_template('crypto/asymmetric.html', error="No key file provided")
            
            key_file = request.files['key']
            if key_file.filename == '':
                return render_template('crypto/asymmetric.html', error="No key file selected")
            
            # Save the uploaded key
            key_filename = secure_filename(key_file.filename)
            key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
            key_file.save(key_path)
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"encrypted_{timestamp}.bin"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Encrypt data
            if is_file:
                result = asymmetric.encrypt_file(data, key_path, output_file=output_path)
            else:
                result = asymmetric.encrypt_text(data, key_path, output_file=output_path)
            
            if result:
                return render_template('crypto/asymmetric.html', result=result, output_file=output_filename)
        
        elif action == 'decrypt':
            # Check if data file was uploaded
            if 'data' not in request.files:
                return render_template('crypto/asymmetric.html', error="No data file provided")
            
            data_file = request.files['data']
            if data_file.filename == '':
                return render_template('crypto/asymmetric.html', error="No data file selected")
            
            # Save the uploaded data
            data_filename = secure_filename(data_file.filename)
            data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
            data_file.save(data_path)
            
            # Check if key file was uploaded
            if 'key' not in request.files:
                return render_template('crypto/asymmetric.html', error="No key file provided")
            
            key_file = request.files['key']
            if key_file.filename == '':
                return render_template('crypto/asymmetric.html', error="No key file selected")
            
            # Save the uploaded key
            key_filename = secure_filename(key_file.filename)
            key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
            key_file.save(key_path)
            
            # Get parameters
            password = request.form.get('password')
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"decrypted_{timestamp}.txt"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Decrypt data
            is_file = request.form.get('is_file') == 'true'
            if is_file:
                result = asymmetric.decrypt_file(data_path, key_path, output_file=output_path, password=password)
            else:
                result = asymmetric.decrypt_text(data_path, key_path, output_file=output_path, password=password)
            
            if result:
                return render_template('crypto/asymmetric.html', result=result, output_file=output_filename)
    
    return render_template('crypto/asymmetric.html')

@app.route('/crypto/hash', methods=['GET', 'POST'])
def crypto_hash():
    """Handle hash requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'calculate':
            # Get data to hash
            data = request.form.get('data')
            data_file = None
            
            if 'data_file' in request.files:
                data_file = request.files['data_file']
            
            if (not data or data.strip() == '') and (not data_file or data_file.filename == ''):
                return render_template('crypto/hash.html', error="No data provided")
            
            # If data file was uploaded, use that instead of text input
            is_file = False
            if data_file and data_file.filename != '':
                data_filename = secure_filename(data_file.filename)
                data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
                data_file.save(data_path)
                data = data_path
                is_file = True
            
            # Get parameters
            algorithm = request.form.get('algorithm', 'sha256')
            
            # Calculate hash
            if is_file:
                result = hashing.hash_file(data, algorithm=algorithm)
            else:
                result = hashing.hash_text(data, algorithm=algorithm)
            
            return render_template('crypto/hash.html', result=result)
        
        elif action == 'verify':
            # Get data to verify
            data = request.form.get('data')
            data_file = None
            
            if 'data_file' in request.files:
                data_file = request.files['data_file']
            
            if (not data or data.strip() == '') and (not data_file or data_file.filename == ''):
                return render_template('crypto/hash.html', error="No data provided")
            
            # If data file was uploaded, use that instead of text input
            is_file = False
            if data_file and data_file.filename != '':
                data_filename = secure_filename(data_file.filename)
                data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
                data_file.save(data_path)
                data = data_path
                is_file = True
            
            # Get parameters
            hash_value = request.form.get('hash')
            algorithm = request.form.get('algorithm', 'sha256')
            
            if not hash_value:
                return render_template('crypto/hash.html', error="No hash value provided")
            
            # Verify hash
            if is_file:
                result = hashing.verify_file_hash(data, hash_value, algorithm=algorithm)
            else:
                result = hashing.verify_text_hash(data, hash_value, algorithm=algorithm)
            
            return render_template('crypto/hash.html', result=result)
    
    return render_template('crypto/hash.html')

@app.route('/crypto/password', methods=['GET', 'POST'])
def crypto_password():
    """Handle password requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'analyze':
            # Get password to analyze
            password_value = request.form.get('password')
            
            if not password_value:
                return render_template('crypto/password.html', error="No password provided")
            
            # Analyze password strength
            result = password.analyze_strength(password_value)
            
            return render_template('crypto/password.html', result=result)
        
        elif action == 'generate':
            # Get parameters
            length = request.form.get('length', 16)
            include_symbols = request.form.get('include_symbols') == 'on'
            include_numbers = request.form.get('include_numbers') == 'on'
            include_uppercase = request.form.get('include_uppercase') == 'on'
            include_lowercase = request.form.get('include_lowercase') == 'on'
            
            if length:
                length = int(length)
            
            # Generate password
            result = password.generate_password(
                length=length,
                include_symbols=include_symbols,
                include_numbers=include_numbers,
                include_uppercase=include_uppercase,
                include_lowercase=include_lowercase
            )
            
            return render_template('crypto/password.html', result=result)
    
    return render_template('crypto/password.html')

@app.route('/crypto/signature', methods=['GET', 'POST'])
def crypto_signature():
    """Handle digital signature requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'sign':
            # Get data to sign
            data = request.form.get('data')
            data_file = None
            
            if 'data_file' in request.files:
                data_file = request.files['data_file']
            
            if (not data or data.strip() == '') and (not data_file or data_file.filename == ''):
                return render_template('crypto/signature.html', error="No data provided")
            
            # If data file was uploaded, use that instead of text input
            is_file = False
            if data_file and data_file.filename != '':
                data_filename = secure_filename(data_file.filename)
                data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
                data_file.save(data_path)
                data = data_path
                is_file = True
            
            # Check if key file was uploaded
            if 'key' not in request.files:
                return render_template('crypto/signature.html', error="No key file provided")
            
            key_file = request.files['key']
            if key_file.filename == '':
                return render_template('crypto/signature.html', error="No key file selected")
            
            # Save the uploaded key
            key_filename = secure_filename(key_file.filename)
            key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
            key_file.save(key_path)
            
            # Get parameters
            password = request.form.get('password')
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"signature_{timestamp}.sig"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Sign data
            if is_file:
                result = signatures.sign_file(data, key_path, output_file=output_path, password=password)
            else:
                result = signatures.sign_text(data, key_path, output_file=output_path, password=password)
            
            if result:
                return render_template('crypto/signature.html', result=result, output_file=output_filename)
        
        elif action == 'verify':
            # Get data to verify
            data = request.form.get('data')
            data_file = None
            
            if 'data_file' in request.files:
                data_file = request.files['data_file']
            
            if (not data or data.strip() == '') and (not data_file or data_file.filename == ''):
                return render_template('crypto/signature.html', error="No data provided")
            
            # If data file was uploaded, use that instead of text input
            is_file = False
            if data_file and data_file.filename != '':
                data_filename = secure_filename(data_file.filename)
                data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
                data_file.save(data_path)
                data = data_path
                is_file = True
            
            # Check if signature file was uploaded
            if 'signature' not in request.files:
                return render_template('crypto/signature.html', error="No signature file provided")
            
            signature_file = request.files['signature']
            if signature_file.filename == '':
                return render_template('crypto/signature.html', error="No signature file selected")
            
            # Save the uploaded signature
            signature_filename = secure_filename(signature_file.filename)
            signature_path = os.path.join(app.config['UPLOAD_FOLDER'], signature_filename)
            signature_file.save(signature_path)
            
            # Check if key file was uploaded
            if 'key' not in request.files:
                return render_template('crypto/signature.html', error="No key file provided")
            
            key_file = request.files['key']
            if key_file.filename == '':
                return render_template('crypto/signature.html', error="No key file selected")
            
            # Save the uploaded key
            key_filename = secure_filename(key_file.filename)
            key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
            key_file.save(key_path)
            
            # Verify signature
            if is_file:
                result = signatures.verify_file(data, signature_path, key_path)
            else:
                result = signatures.verify_text(data, signature_path, key_path)
            
            return render_template('crypto/signature.html', result=result)
    
    return render_template('crypto/signature.html')

@app.route('/crypto/key', methods=['GET', 'POST'])
def crypto_key():
    """Handle key management requests."""
    # Create key manager
    key_manager = keys.KeyManager()
    
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'generate-rsa':
            # Get parameters
            name = request.form.get('name')
            key_size = request.form.get('key_size', 2048)
            password = request.form.get('password')
            overwrite = request.form.get('overwrite') == 'on'
            
            if not name:
                return render_template('crypto/key.html', error="No key name provided")
            
            if key_size:
                key_size = int(key_size)
            
            # Generate RSA key pair
            result = key_manager.generate_rsa_key_pair(
                name,
                key_size=key_size,
                password=password,
                overwrite=overwrite
            )
            
            return render_template('crypto/key.html', result=result)
        
        elif action == 'generate-ec':
            # Get parameters
            name = request.form.get('name')
            curve = request.form.get('curve', 'secp256r1')
            password = request.form.get('password')
            overwrite = request.form.get('overwrite') == 'on'
            
            if not name:
                return render_template('crypto/key.html', error="No key name provided")
            
            # Generate EC key pair
            result = key_manager.generate_ec_key_pair(
                name,
                curve=curve,
                password=password,
                overwrite=overwrite
            )
            
            return render_template('crypto/key.html', result=result)
        
        elif action == 'generate-symmetric':
            # Get parameters
            name = request.form.get('name')
            key_size = request.form.get('key_size', 256)
            overwrite = request.form.get('overwrite') == 'on'
            
            if not name:
                return render_template('crypto/key.html', error="No key name provided")
            
            if key_size:
                key_size = int(key_size)
            
            # Generate symmetric key
            result = key_manager.generate_symmetric_key(
                name,
                key_size=key_size,
                overwrite=overwrite
            )
            
            return render_template('crypto/key.html', result=result)
        
        elif action == 'import':
            # Get parameters
            name = request.form.get('name')
            key_type = request.form.get('key_type', 'auto')
            password = request.form.get('password')
            overwrite = request.form.get('overwrite') == 'on'
            
            if not name:
                return render_template('crypto/key.html', error="No key name provided")
            
            # Check if key file was uploaded
            if 'key_file' not in request.files:
                return render_template('crypto/key.html', error="No key file provided")
            
            key_file = request.files['key_file']
            if key_file.filename == '':
                return render_template('crypto/key.html', error="No key file selected")
            
            # Save the uploaded key
            key_filename = secure_filename(key_file.filename)
            key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
            key_file.save(key_path)
            
            # Import key
            result = key_manager.import_key(
                name,
                key_path,
                key_type=key_type,
                password=password,
                overwrite=overwrite
            )
            
            return render_template('crypto/key.html', result=result)
        
        elif action == 'export':
            # Get parameters
            name = request.form.get('name')
            key_type = request.form.get('key_type', 'public')
            password = request.form.get('password')
            
            if not name:
                return render_template('crypto/key.html', error="No key name provided")
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"{name}_{key_type}_{timestamp}.pem"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Export key
            result = key_manager.export_key(
                name,
                output_file=output_path,
                key_type=key_type,
                password=password
            )
            
            if result:
                return render_template('crypto/key.html', result=result, output_file=output_filename)
        
        elif action == 'delete':
            # Get parameters
            name = request.form.get('name')
            
            if not name:
                return render_template('crypto/key.html', error="No key name provided")
            
            # Delete key
            result = key_manager.delete_key(name)
            
            return render_template('crypto/key.html', result=result)
        
        elif action == 'list':
            # List keys
            result = key_manager.list_keys()
            
            return render_template('crypto/key.html', result=result)
        
        elif action == 'info':
            # Get parameters
            name = request.form.get('name')
            
            if not name:
                return render_template('crypto/key.html', error="No key name provided")
            
            # Get key info
            result = key_manager.get_key_info(name)
            
            return render_template('crypto/key.html', result=result)
        
        elif action == 'generate-cert':
            # Get parameters
            name = request.form.get('name')
            subject = request.form.get('subject')
            valid_days = request.form.get('valid_days', 365)
            key_type = request.form.get('key_type', 'rsa')
            key_size = request.form.get('key_size', 2048)
            curve = request.form.get('curve', 'secp256r1')
            password = request.form.get('password')
            overwrite = request.form.get('overwrite') == 'on'
            
            if not name:
                return render_template('crypto/key.html', error="No key name provided")
            
            if not subject:
                return render_template('crypto/key.html', error="No subject name provided")
            
            if valid_days:
                valid_days = int(valid_days)
            
            if key_size:
                key_size = int(key_size)
            
            # Generate certificate
            result = key_manager.generate_certificate(
                name,
                subject,
                valid_days=valid_days,
                key_type=key_type,
                key_size=key_size,
                curve=curve,
                password=password,
                overwrite=overwrite
            )
            
            return render_template('crypto/key.html', result=result)
    
    return render_template('crypto/key.html')

# Tracking Routes
@app.route('/tracking')
def tracking_dashboard():
    """Render the tracking dashboard."""
    return render_template('tracking/dashboard.html')

@app.route('/tracking/camera', methods=['GET', 'POST'])
def tracking_camera():
    """Handle camera requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'capture':
            # Get parameters
            camera_id = request.form.get('camera_id', 0)
            delay = request.form.get('delay', 3)
            
            if camera_id:
                camera_id = int(camera_id)
            
            if delay:
                delay = int(delay)
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"capture_{timestamp}.jpg"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Capture image
            result = camera.capture_image(output_file=output_path, camera_id=camera_id, delay=delay)
            
            if result:
                return render_template('tracking/camera.html', result=result, output_file=output_filename)
        
        elif action == 'scan':
            # Get parameters
            camera_id = request.form.get('camera_id', 0)
            extract_text = request.form.get('extract_text') == 'on'
            
            if camera_id:
                camera_id = int(camera_id)
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"scan_{timestamp}.jpg"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Scan document
            result = camera.scan_document(output_file=output_path, camera_id=camera_id, extract_text=extract_text)
            
            if result:
                return render_template('tracking/camera.html', result=result, output_file=output_filename)
        
        elif action == 'analyze':
            # Check if image file was uploaded
            if 'image' not in request.files:
                return render_template('tracking/camera.html', error="No image file provided")
            
            image_file = request.files['image']
            if image_file.filename == '':
                return render_template('tracking/camera.html', error="No image file selected")
            
            if image_file and allowed_file(image_file.filename):
                # Save the uploaded image
                image_filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                image_file.save(image_path)
                
                # Get parameters
                extract_metadata = request.form.get('metadata') == 'on'
                detect_manipulation = request.form.get('manipulation') == 'on'
                enhance_image = request.form.get('enhance') == 'on'
                
                # Generate output directory
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                output_dirname = f"analysis_{timestamp}"
                output_dir = os.path.join(app.config['RESULTS_FOLDER'], output_dirname)
                os.makedirs(output_dir, exist_ok=True)
                
                # Analyze image
                result = camera.analyze_image(
                    image_path,
                    output_dir=output_dir,
                    extract_metadata=extract_metadata,
                    detect_manipulation=detect_manipulation,
                    enhance_image=enhance_image
                )
                
                if result:
                    return render_template('tracking/camera.html', result=result, output_dir=output_dirname)
            else:
                return render_template('tracking/camera.html', error="Invalid file type")
    
    return render_template('tracking/camera.html')

@app.route('/tracking/alias', methods=['GET', 'POST'])
def tracking_alias():
    """Handle alias tracking requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'search':
            # Get parameters
            name = request.form.get('name')
            state = request.form.get('state')
            search_pacer = request.form.get('pacer') == 'on'
            search_property = request.form.get('property') == 'on'
            
            if not name:
                return render_template('tracking/alias.html', error="No name provided")
            
            # Search for aliases
            result = alias.search_aliases(
                name,
                state=state,
                search_pacer=search_pacer,
                search_property=search_property
            )
            
            return render_template('tracking/alias.html', result=result)
        
        elif action == 'track':
            # Get parameters
            name = request.form.get('name')
            add_alias = request.form.get('add_alias')
            remove_alias = request.form.get('remove_alias')
            list_aliases = request.form.get('list') == 'on'
            
            if not name:
                return render_template('tracking/alias.html', error="No name provided")
            
            # Track aliases
            if add_alias:
                result = alias.add_alias(name, add_alias)
            elif remove_alias:
                result = alias.remove_alias(name, remove_alias)
            elif list_aliases:
                result = alias.list_aliases(name)
            else:
                result = alias.get_tracking_status(name)
            
            return render_template('tracking/alias.html', result=result)
    
    return render_template('tracking/alias.html')

@app.route('/tracking/report', methods=['GET', 'POST'])
def tracking_report():
    """Handle report requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'generate':
            # Get parameters
            subject = request.form.get('subject')
            template = request.form.get('template', 'background')
            include_osint = request.form.get('include_osint') == 'on'
            include_aliases = request.form.get('include_aliases') == 'on'
            
            if not subject:
                return render_template('tracking/report.html', error="No subject provided")
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"report_{timestamp}.pdf"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Generate report
            result = reports.generate_report(
                subject,
                template=template,
                output_file=output_path,
                include_osint=include_osint,
                include_aliases=include_aliases
            )
            
            if result:
                return render_template('tracking/report.html', result=result, output_file=output_filename)
        
        elif action == 'evidence':
            # Get parameters
            case = request.form.get('case')
            add_evidence = None
            remove_evidence = request.form.get('remove')
            list_evidence = request.form.get('list') == 'on'
            
            if not case:
                return render_template('tracking/report.html', error="No case name provided")
            
            # Check if evidence file was uploaded
            if 'add' in request.files:
                evidence_file = request.files['add']
                if evidence_file.filename != '':
                    # Save the uploaded evidence
                    evidence_filename = secure_filename(evidence_file.filename)
                    evidence_path = os.path.join(app.config['UPLOAD_FOLDER'], evidence_filename)
                    evidence_file.save(evidence_path)
                    add_evidence = evidence_path
            
            # Manage evidence
            if add_evidence:
                result = reports.add_evidence(case, add_evidence)
            elif remove_evidence:
                result = reports.remove_evidence(case, remove_evidence)
            elif list_evidence:
                result = reports.list_evidence(case)
            else:
                return render_template('tracking/report.html', error="No evidence action specified")
            
            return render_template('tracking/report.html', result=result)
    
    return render_template('tracking/report.html')

@app.route('/tracking/crossref', methods=['GET', 'POST'])
def tracking_crossref():
    """Handle cross-reference requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'analyze':
            # Get parameters
            targets = request.form.get('targets')
            depth = request.form.get('depth', 2)
            
            if not targets:
                return render_template('tracking/crossref.html', error="No targets provided")
            
            if depth:
                depth = int(depth)
            
            # Split targets into list
            target_list = [t.strip() for t in targets.split(',')]
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"connections_{timestamp}.json"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Analyze connections
            result = crossref.analyze_connections(target_list, output_file=output_path, depth=depth)
            
            if result:
                return render_template('tracking/crossref.html', result=result, output_file=output_filename)
        
        elif action == 'verify':
            # Get parameters
            name = request.form.get('name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            address = request.form.get('address')
            
            if not name:
                return render_template('tracking/crossref.html', error="No name provided")
            
            # Verify identity
            result = crossref.verify_identity(
                name,
                email=email,
                phone=phone,
                address=address
            )
            
            return render_template('tracking/crossref.html', result=result)
    
    return render_template('tracking/crossref.html')

@app.route('/tracking/visualize', methods=['GET', 'POST'])
def tracking_visualize():
    """Handle visualization requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'network':
            # Check if data file was uploaded
            if 'data' not in request.files:
                return render_template('tracking/visualize.html', error="No data file provided")
            
            data_file = request.files['data']
            if data_file.filename == '':
                return render_template('tracking/visualize.html', error="No data file selected")
            
            # Save the uploaded data
            data_filename = secure_filename(data_file.filename)
            data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
            data_file.save(data_path)
            
            # Get parameters
            output_format = request.form.get('format', 'html')
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"network_{timestamp}.{output_format}"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Create network graph
            result = visualize.create_network_graph(data_path, output_file=output_path, output_format=output_format)
            
            if result:
                return render_template('tracking/visualize.html', result=result, output_file=output_filename)
        
        elif action == 'map':
            # Check if data file was uploaded
            if 'data' not in request.files:
                return render_template('tracking/visualize.html', error="No data file provided")
            
            data_file = request.files['data']
            if data_file.filename == '':
                return render_template('tracking/visualize.html', error="No data file selected")
            
            # Save the uploaded data
            data_filename = secure_filename(data_file.filename)
            data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
            data_file.save(data_path)
            
            # Get parameters
            output_format = request.form.get('format', 'html')
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"map_{timestamp}.{output_format}"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Create geographic map
            result = visualize.create_geographic_map(data_path, output_file=output_path, output_format=output_format)
            
            if result:
                return render_template('tracking/visualize.html', result=result, output_file=output_filename)
    
    return render_template('tracking/visualize.html')

@app.route('/tracking/timeline', methods=['GET', 'POST'])
def tracking_timeline():
    """Handle timeline requests."""
    if request.method == 'POST':
        action = request.form.get('action')
        result = None
        
        if action == 'create':
            # Get parameters
            name = request.form.get('name')
            description = request.form.get('description')
            
            if not name:
                return render_template('tracking/timeline.html', error="No timeline name provided")
            
            # Create timeline
            result = timeline.create_timeline(name, description=description)
            
            return render_template('tracking/timeline.html', result=result)
        
        elif action == 'add':
            # Get parameters
            timeline_name = request.form.get('timeline')
            date = request.form.get('date')
            time = request.form.get('time')
            description = request.form.get('description')
            category = request.form.get('category')
            
            if not timeline_name:
                return render_template('tracking/timeline.html', error="No timeline name provided")
            
            if not date:
                return render_template('tracking/timeline.html', error="No date provided")
            
            if not description:
                return render_template('tracking/timeline.html', error="No description provided")
            
            # Add event to timeline
            result = timeline.add_event(
                timeline_name,
                date,
                description,
                time=time,
                category=category
            )
            
            return render_template('tracking/timeline.html', result=result)
        
        elif action == 'visualize':
            # Get parameters
            timeline_name = request.form.get('timeline')
            output_format = request.form.get('format', 'html')
            
            if not timeline_name:
                return render_template('tracking/timeline.html', error="No timeline name provided")
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_filename = f"timeline_{timestamp}.{output_format}"
            output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
            
            # Visualize timeline
            result = timeline.visualize_timeline(timeline_name, output_file=output_path, output_format=output_format)
            
            if result:
                return render_template('tracking/timeline.html', result=result, output_file=output_filename)
    
    return render_template('tracking/timeline.html')

# Generator Routes
@app.route('/generate')
def generate_dashboard():
    """Render the generator dashboard."""
    return render_template('generate/dashboard.html')

@app.route('/generate/username', methods=['GET', 'POST'])
def generate_username():
    """Handle username generator requests."""
    if request.method == 'POST':
        # Get parameters
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        count = request.form.get('count', 10)
        include_numbers = request.form.get('include_numbers') == 'on'
        include_special = request.form.get('include_special') == 'on'
        
        if not first_name and not last_name:
            return render_template('generate/username.html', error="No name provided")
        
        if count:
            count = int(count)
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"usernames_{timestamp}.txt"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Generate usernames
        result = username_gen.generate_usernames(
            first_name=first_name,
            last_name=last_name,
            count=count,
            include_numbers=include_numbers,
            include_special=include_special,
            output_file=output_path
        )
        
        if result:
            return render_template('generate/username.html', result=result, output_file=output_filename)
    
    return render_template('generate/username.html')

@app.route('/generate/email', methods=['GET', 'POST'])
def generate_email():
    """Handle email generator requests."""
    if request.method == 'POST':
        # Get parameters
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        domain = request.form.get('domain')
        count = request.form.get('count', 10)
        
        if not first_name and not last_name:
            return render_template('generate/email.html', error="No name provided")
        
        if count:
            count = int(count)
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"emails_{timestamp}.txt"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Generate emails
        result = email_gen.generate_emails(
            first_name=first_name,
            last_name=last_name,
            domain=domain,
            count=count,
            output_file=output_path
        )
        
        if result:
            return render_template('generate/email.html', result=result, output_file=output_filename)
    
    return render_template('generate/email.html')

@app.route('/generate/password', methods=['GET', 'POST'])
def generate_password():
    """Handle password generator requests."""
    if request.method == 'POST':
        # Get parameters
        length = request.form.get('length', 16)
        count = request.form.get('count', 1)
        include_symbols = request.form.get('include_symbols') == 'on'
        include_numbers = request.form.get('include_numbers') == 'on'
        include_uppercase = request.form.get('include_uppercase') == 'on'
        include_lowercase = request.form.get('include_lowercase') == 'on'
        
        if length:
            length = int(length)
        
        if count:
            count = int(count)
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"passwords_{timestamp}.txt"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Generate passwords
        result = password_gen.generate_passwords(
            length=length,
            count=count,
            include_symbols=include_symbols,
            include_numbers=include_numbers,
            include_uppercase=include_uppercase,
            include_lowercase=include_lowercase,
            output_file=output_path
        )
        
        if result:
            return render_template('generate/password.html', result=result, output_file=output_filename)
    
    return render_template('generate/password.html')

@app.route('/generate/identity', methods=['GET', 'POST'])
def generate_identity():
    """Handle identity generator requests."""
    if request.method == 'POST':
        # Get parameters
        gender = request.form.get('gender', 'random')
        country = request.form.get('country', 'US')
        age_min = request.form.get('age_min', 18)
        age_max = request.form.get('age_max', 80)
        count = request.form.get('count', 1)
        
        if age_min:
            age_min = int(age_min)
        
        if age_max:
            age_max = int(age_max)
        
        if count:
            count = int(count)
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"identities_{timestamp}.json"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Generate identities
        result = identity.generate_identities(
            gender=gender,
            country=country,
            age_min=age_min,
            age_max=age_max,
            count=count,
            output_file=output_path
        )
        
        if result:
            return render_template('generate/identity.html', result=result, output_file=output_filename)
    
    return render_template('generate/identity.html')

@app.route('/generate/document', methods=['GET', 'POST'])
def generate_document():
    """Handle document generator requests."""
    if request.method == 'POST':
        # Get parameters
        doc_type = request.form.get('type')
        name = request.form.get('name')
        template_file = None
        
        if 'template' in request.files:
            template_file = request.files['template']
        
        if not doc_type:
            return render_template('generate/document.html', error="No document type provided")
        
        # If template file was uploaded, save it
        template_path = None
        if template_file and template_file.filename != '':
            template_filename = secure_filename(template_file.filename)
            template_path = os.path.join(app.config['UPLOAD_FOLDER'], template_filename)
            template_file.save(template_path)
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"{doc_type}_{timestamp}.pdf"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Generate document
        result = document.generate_document(
            doc_type=doc_type,
            name=name,
            template=template_path,
            output_file=output_path
        )
        
        if result:
            return render_template('generate/document.html', result=result, output_file=output_filename)
    
    return render_template('generate/document.html')

# Decoder Routes
@app.route('/decode')
def decode_dashboard():
    """Render the decoder dashboard."""
    return render_template('decode/dashboard.html')

@app.route('/decode/text', methods=['GET', 'POST'])
def decode_text():
    """Handle text decoder requests."""
    if request.method == 'POST':
        # Get data to decode
        data = request.form.get('data')
        
        if not data:
            return render_template('decode/text.html', error="No data provided")
        
        # Get parameters
        encoding = request.form.get('encoding', 'auto')
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"decoded_{timestamp}.txt"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Decode text
        result = decoders.decode_text(data, encoding=encoding, output_file=output_path)
        
        if result:
            return render_template('decode/text.html', result=result, output_file=output_filename)
    
    return render_template('decode/text.html')

@app.route('/decode/file', methods=['GET', 'POST'])
def decode_file():
    """Handle file decoder requests."""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            return render_template('decode/file.html', error="No file provided")
        
        file = request.files['file']
        if file.filename == '':
            return render_template('decode/file.html', error="No file selected")
        
        # Save the uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get parameters
        encoding = request.form.get('encoding', 'auto')
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"decoded_{timestamp}.bin"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Decode file
        result = decoders.decode_file(file_path, encoding=encoding, output_file=output_path)
        
        if result:
            return render_template('decode/file.html', result=result, output_file=output_filename)
    
    return render_template('decode/file.html')

@app.route('/decode/binary', methods=['GET', 'POST'])
def decode_binary():
    """Handle binary analyzer requests."""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            return render_template('decode/binary.html', error="No file provided")
        
        file = request.files['file']
        if file.filename == '':
            return render_template('decode/binary.html', error="No file selected")
        
        # Save the uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get parameters
        extract_strings = request.form.get('strings') == 'on'
        analyze_headers = request.form.get('headers') == 'on'
        calculate_entropy = request.form.get('entropy') == 'on'
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"analysis_{timestamp}.json"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Analyze binary
        result = decoders.analyze_binary(
            file_path,
            output_file=output_path,
            extract_strings=extract_strings,
            analyze_headers=analyze_headers,
            calculate_entropy=calculate_entropy
        )
        
        if result:
            return render_template('decode/binary.html', result=result, output_file=output_filename)
    
    return render_template('decode/binary.html')

# Network Routes
@app.route('/network')
def network_dashboard():
    """Render the network reconnaissance dashboard."""
    return render_template('network/dashboard.html')

@app.route('/network/scan', methods=['GET', 'POST'])
def network_scan():
    """Handle network scan requests."""
    if request.method == 'POST':
        # Get parameters
        target = request.form.get('target')
        scan_type = request.form.get('scan_type', 'basic')
        
        if not target:
            return render_template('network/scan.html', error="No target provided")
        
        # Create network reconnaissance object
        net_recon = NetworkRecon()
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"scan_{timestamp}.json"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Scan host
        result = net_recon.scan_host(target, scan_type=scan_type, output_file=output_path)
        
        if result:
            return render_template('network/scan.html', result=result, output_file=output_filename)
    
    return render_template('network/scan.html')

@app.route('/network/discover', methods=['GET', 'POST'])
def network_discover():
    """Handle network discovery requests."""
    if request.method == 'POST':
        # Get parameters
        network = request.form.get('network')
        method = request.form.get('method', 'ping')
        
        if not network:
            return render_template('network/discover.html', error="No network provided")
        
        # Create network reconnaissance object
        net_recon = NetworkRecon()
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"discover_{timestamp}.json"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Discover hosts
        result = net_recon.discover_network(network, method=method, output_file=output_path)
        
        if result:
            return render_template('network/discover.html', result=result, output_file=output_filename)
    
    return render_template('network/discover.html')

@app.route('/network/ports', methods=['GET', 'POST'])
def network_ports():
    """Handle port scan requests."""
    if request.method == 'POST':
        # Get parameters
        target = request.form.get('target')
        ports = request.form.get('ports', 'common')
        protocol = request.form.get('protocol', 'tcp')
        
        if not target:
            return render_template('network/ports.html', error="No target provided")
        
        # Create network reconnaissance object
        net_recon = NetworkRecon()
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"ports_{timestamp}.json"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Scan ports
        result = net_recon.scan_ports(target, ports=ports, protocol=protocol, output_file=output_path)
        
        if result:
            return render_template('network/ports.html', result=result, output_file=output_filename)
    
    return render_template('network/ports.html')

@app.route('/network/os', methods=['GET', 'POST'])
def network_os():
    """Handle OS detection requests."""
    if request.method == 'POST':
        # Get parameters
        target = request.form.get('target')
        
        if not target:
            return render_template('network/os.html', error="No target provided")
        
        # Create network reconnaissance object
        net_recon = NetworkRecon()
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"os_{timestamp}.json"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Detect OS
        result = net_recon.os_detection(target, output_file=output_path)
        
        if result:
            return render_template('network/os.html', result=result, output_file=output_filename)
    
    return render_template('network/os.html')

@app.route('/network/vulnerability', methods=['GET', 'POST'])
def network_vulnerability():
    """Handle vulnerability scan requests."""
    if request.method == 'POST':
        # Get parameters
        target = request.form.get('target')
        
        if not target:
            return render_template('network/vulnerability.html', error="No target provided")
        
        # Create network reconnaissance object
        net_recon = NetworkRecon()
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"vulnerability_{timestamp}.json"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Scan for vulnerabilities
        result = net_recon.vulnerability_scan(target, output_file=output_path)
        
        if result:
            return render_template('network/vulnerability.html', result=result, output_file=output_filename)
    
    return render_template('network/vulnerability.html')

@app.route('/network/dns', methods=['GET', 'POST'])
def network_dns():
    """Handle DNS enumeration requests."""
    if request.method == 'POST':
        # Get parameters
        domain = request.form.get('domain')
        
        if not domain:
            return render_template('network/dns.html', error="No domain provided")
        
        # Create network reconnaissance object
        net_recon = NetworkRecon()
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"dns_{timestamp}.json"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Enumerate DNS
        result = net_recon.dns_enumeration(domain, output_file=output_path)
        
        if result:
            return render_template('network/dns.html', result=result, output_file=output_filename)
    
    return render_template('network/dns.html')

@app.route('/network/capture', methods=['GET', 'POST'])
def network_capture():
    """Handle packet capture requests."""
    if request.method == 'POST':
        # Get parameters
        interface = request.form.get('interface')
        filter = request.form.get('filter')
        count = request.form.get('count', 100)
        
        if not interface:
            return render_template('network/capture.html', error="No interface provided")
        
        if count:
            count = int(count)
        
        # Create network reconnaissance object
        net_recon = NetworkRecon()
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_filename = f"capture_{timestamp}.pcap"
        output_path = os.path.join(app.config['RESULTS_FOLDER'], output_filename)
        
        # Capture packets
        result = net_recon.capture_packets(interface, filter=filter, count=count, output_file=output_path)
        
        if result:
            return render_template('network/capture.html', result=result, output_file=output_filename)
    
    return render_template('network/capture.html')

@app.route('/network/analyze', methods=['GET', 'POST'])
def network_analyze():
    """Handle packet analysis requests."""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            return render_template('network/analyze.html', error="No file provided")
        
        file = request.files['file']
        if file.filename == '':
            return render_template('network/analyze.html', error="No file selected")
        
        # Save the uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Create network reconnaissance object
        net_recon = NetworkRecon()
        
        # Analyze PCAP
        result = net_recon.analyze_pcap(file_path)
        
        return render_template('network/analyze.html', result=result)
    
    return render_template('network/analyze.html')

@app.route('/network/trace', methods=['GET', 'POST'])
def network_trace():
    """Handle traceroute requests."""
    if request.method == 'POST':
        # Get parameters
        target = request.form.get('target')
        max_hops = request.form.get('max_hops', 30)
        
        if not target:
            return render_template('network/trace.html', error="No target provided")
        
        if max_hops:
            max_hops = int(max_hops)
        
        # Create network reconnaissance object
        net_recon = NetworkRecon()
        
        # Trace route
        result = net_recon.trace_route(target, max_hops=max_hops)
        
        return render_template('network/trace.html', result=result)
    
    return render_template('network/trace.html')

# File download route
@app.route('/download/<path:filename>')
def download_file(filename):
    """Download a file from the results folder."""
    return send_file(os.path.join(app.config['RESULTS_FOLDER'], filename), as_attachment=True)

def main():
    """Main entry point for the web GUI."""
    parser = argparse.ArgumentParser(description='Ultimate PI Tool - Web GUI')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main()
