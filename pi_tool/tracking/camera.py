"""
Forensic Camera module for the Ultimate PI Tool.

This module provides functionality for capturing, analyzing, and processing images
with forensic capabilities for investigations.
"""

import os
import sys
import cv2
import numpy as np
import PIL.Image
import PIL.ExifTags
from datetime import datetime
from rich.console import Console
from rich.table import Table
import matplotlib.pyplot as plt
from io import BytesIO

console = Console()

class ForensicCamera:
    """Forensic Camera class for image capture and analysis."""
    
    def __init__(self):
        """Initialize the Forensic Camera module."""
        pass
    
    def capture_image(self, output_path=None):
        """Capture an image from the camera."""
        console.print("[bold blue]Initializing camera for image capture[/]")
        
        try:
            # Initialize camera
            cap = cv2.VideoCapture(0)
            
            if not cap.isOpened():
                console.print("[bold red]Error:[/] Could not open camera")
                return False
            
            # Display instructions
            console.print("[bold blue]Camera initialized. Press SPACE to capture, ESC to cancel.[/]")
            
            while True:
                # Capture frame-by-frame
                ret, frame = cap.read()
                
                if not ret:
                    console.print("[bold red]Error:[/] Failed to capture frame")
                    break
                
                # Display the frame
                cv2.imshow('Forensic Camera - Press SPACE to capture, ESC to cancel', frame)
                
                # Wait for key press
                key = cv2.waitKey(1)
                
                # If ESC is pressed, exit
                if key == 27:  # ESC key
                    console.print("[bold yellow]Capture cancelled[/]")
                    break
                
                # If SPACE is pressed, capture the image
                elif key == 32:  # SPACE key
                    # Determine output path if not specified
                    if not output_path:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        output_path = f"forensic_capture_{timestamp}.jpg"
                    
                    # Save the image
                    cv2.imwrite(output_path, frame)
                    console.print(f"[bold green]Image captured and saved to:[/] [bold]{output_path}[/]")
                    
                    # Add metadata
                    self._add_metadata(output_path)
                    
                    break
            
            # Release the camera
            cap.release()
            cv2.destroyAllWindows()
            
            # Analyze the captured image if it was saved
            if os.path.exists(output_path):
                self.analyze_image(output_path)
                return True
            
            return False
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def analyze_image(self, image_path):
        """Analyze an image for forensic purposes."""
        console.print(f"[bold blue]Analyzing image:[/] [bold green]{image_path}[/]")
        
        try:
            # Check if file exists
            if not os.path.exists(image_path):
                console.print(f"[bold red]Error:[/] Image file not found: {image_path}")
                return False
            
            # Read the image
            image = cv2.imread(image_path)
            
            if image is None:
                console.print(f"[bold red]Error:[/] Failed to read image: {image_path}")
                return False
            
            # Get basic image information
            height, width, channels = image.shape
            
            console.print("[bold]Image Information:[/]")
            console.print(f"Dimensions: {width} x {height} pixels")
            console.print(f"Channels: {channels}")
            console.print(f"File size: {os.path.getsize(image_path)} bytes")
            
            # Extract metadata
            metadata = self.extract_metadata(image_path, display=False)
            
            if metadata:
                console.print("[bold]Metadata:[/]")
                for key, value in metadata.items():
                    console.print(f"{key}: {value}")
            
            # Perform image analysis
            self._analyze_image_content(image, image_path)
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def scan_document(self, output_path=None):
        """Scan a document and process it for text extraction."""
        console.print("[bold blue]Initializing camera for document scanning[/]")
        
        try:
            # Initialize camera
            cap = cv2.VideoCapture(0)
            
            if not cap.isOpened():
                console.print("[bold red]Error:[/] Could not open camera")
                return False
            
            # Display instructions
            console.print("[bold blue]Camera initialized. Position document in frame, then press SPACE to scan, ESC to cancel.[/]")
            
            while True:
                # Capture frame-by-frame
                ret, frame = cap.read()
                
                if not ret:
                    console.print("[bold red]Error:[/] Failed to capture frame")
                    break
                
                # Display the frame
                cv2.imshow('Document Scanner - Press SPACE to scan, ESC to cancel', frame)
                
                # Wait for key press
                key = cv2.waitKey(1)
                
                # If ESC is pressed, exit
                if key == 27:  # ESC key
                    console.print("[bold yellow]Scan cancelled[/]")
                    break
                
                # If SPACE is pressed, scan the document
                elif key == 32:  # SPACE key
                    # Determine output path if not specified
                    if not output_path:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        output_path = f"document_scan_{timestamp}.jpg"
                    
                    # Process the frame for document scanning
                    processed_frame = self._process_document(frame)
                    
                    # Save the processed image
                    cv2.imwrite(output_path, processed_frame)
                    console.print(f"[bold green]Document scanned and saved to:[/] [bold]{output_path}[/]")
                    
                    # Extract text from the document
                    self._extract_text_from_image(output_path)
                    
                    break
            
            # Release the camera
            cap.release()
            cv2.destroyAllWindows()
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def extract_metadata(self, image_path, display=True):
        """Extract metadata from an image."""
        if display:
            console.print(f"[bold blue]Extracting metadata from image:[/] [bold green]{image_path}[/]")
        
        try:
            # Check if file exists
            if not os.path.exists(image_path):
                if display:
                    console.print(f"[bold red]Error:[/] Image file not found: {image_path}")
                return None
            
            # Open the image with PIL
            img = PIL.Image.open(image_path)
            
            # Extract EXIF data
            exif_data = {}
            
            if hasattr(img, '_getexif') and img._getexif() is not None:
                exif = {
                    PIL.ExifTags.TAGS[k]: v
                    for k, v in img._getexif().items()
                    if k in PIL.ExifTags.TAGS
                }
                
                # Process EXIF data
                for key, value in exif.items():
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8')
                        except UnicodeDecodeError:
                            value = str(value)
                    
                    exif_data[key] = value
            
            # Add basic file information
            file_info = {
                'Filename': os.path.basename(image_path),
                'File Size': f"{os.path.getsize(image_path)} bytes",
                'Image Format': img.format,
                'Image Mode': img.mode,
                'Image Size': f"{img.width} x {img.height} pixels",
                'Creation Time': datetime.fromtimestamp(os.path.getctime(image_path)).strftime('%Y-%m-%d %H:%M:%S'),
                'Modification Time': datetime.fromtimestamp(os.path.getmtime(image_path)).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Combine file info and EXIF data
            metadata = {**file_info, **exif_data}
            
            if display:
                # Create table for display
                table = Table(title=f"Metadata for {os.path.basename(image_path)}")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="green")
                
                for key, value in metadata.items():
                    table.add_row(str(key), str(value))
                
                console.print(table)
            
            return metadata
            
        except Exception as e:
            if display:
                console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def detect_manipulation(self, image_path):
        """Detect potential image manipulation."""
        console.print(f"[bold blue]Analyzing image for manipulation:[/] [bold green]{image_path}[/]")
        
        try:
            # Check if file exists
            if not os.path.exists(image_path):
                console.print(f"[bold red]Error:[/] Image file not found: {image_path}")
                return False
            
            # Read the image
            image = cv2.imread(image_path)
            
            if image is None:
                console.print(f"[bold red]Error:[/] Failed to read image: {image_path}")
                return False
            
            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply error level analysis (ELA)
            ela_image = self._error_level_analysis(image_path)
            
            # Save ELA image
            ela_output = f"{os.path.splitext(image_path)[0]}_ela.jpg"
            cv2.imwrite(ela_output, ela_image)
            console.print(f"[bold green]Error Level Analysis saved to:[/] [bold]{ela_output}[/]")
            
            # Check for noise inconsistencies
            noise_result = self._analyze_noise(gray)
            
            # Check metadata for inconsistencies
            metadata = self.extract_metadata(image_path, display=False)
            metadata_result = self._analyze_metadata_consistency(metadata)
            
            # Display results
            console.print("[bold]Manipulation Analysis Results:[/]")
            console.print(f"Noise Analysis: {noise_result}")
            console.print(f"Metadata Analysis: {metadata_result}")
            console.print("[bold yellow]Note:[/] These results are indicative only and should be verified by a forensic expert.")
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def enhance_image(self, image_path, output_path=None):
        """Enhance an image for better visibility."""
        console.print(f"[bold blue]Enhancing image:[/] [bold green]{image_path}[/]")
        
        try:
            # Check if file exists
            if not os.path.exists(image_path):
                console.print(f"[bold red]Error:[/] Image file not found: {image_path}")
                return False
            
            # Read the image
            image = cv2.imread(image_path)
            
            if image is None:
                console.print(f"[bold red]Error:[/] Failed to read image: {image_path}")
                return False
            
            # Determine output path if not specified
            if not output_path:
                output_path = f"{os.path.splitext(image_path)[0]}_enhanced.jpg"
            
            # Convert to LAB color space
            lab = cv2.cvtColor(image, cv2.COLOR_BGR2LAB)
            
            # Split the LAB image into different channels
            l, a, b = cv2.split(lab)
            
            # Apply CLAHE to L channel
            clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
            cl = clahe.apply(l)
            
            # Merge the CLAHE enhanced L channel with the original A and B channels
            merged = cv2.merge((cl, a, b))
            
            # Convert back to BGR color space
            enhanced = cv2.cvtColor(merged, cv2.COLOR_LAB2BGR)
            
            # Save the enhanced image
            cv2.imwrite(output_path, enhanced)
            console.print(f"[bold green]Enhanced image saved to:[/] [bold]{output_path}[/]")
            
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return False
    
    def _add_metadata(self, image_path):
        """Add forensic metadata to an image."""
        try:
            # Open the image with PIL
            img = PIL.Image.open(image_path)
            
            # Create EXIF data
            exif_data = {
                'Make': 'PI Tool Forensic Camera',
                'Model': 'v1.0',
                'Software': 'Ultimate PI Tool',
                'DateTime': datetime.now().strftime('%Y:%m:%d %H:%M:%S'),
                'ImageDescription': 'Forensic capture',
                'Copyright': 'Ultimate PI Tool'
            }
            
            # Save with EXIF data
            img.save(image_path, exif=exif_data)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Failed to add metadata: {str(e)}")
            return False
    
    def _process_document(self, frame):
        """Process a frame for document scanning."""
        try:
            # Convert to grayscale
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            
            # Apply Gaussian blur
            blur = cv2.GaussianBlur(gray, (5, 5), 0)
            
            # Apply adaptive threshold
            thresh = cv2.adaptiveThreshold(blur, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
            
            # Find contours
            contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            # Find the largest contour (assumed to be the document)
            if contours:
                largest_contour = max(contours, key=cv2.contourArea)
                
                # Approximate the contour to a polygon
                epsilon = 0.02 * cv2.arcLength(largest_contour, True)
                approx = cv2.approxPolyDP(largest_contour, epsilon, True)
                
                # If we have a quadrilateral, perform perspective transform
                if len(approx) == 4:
                    # Order the points
                    pts = approx.reshape(4, 2)
                    rect = self._order_points(pts)
                    
                    # Get width and height of the document
                    width = max(int(np.linalg.norm(rect[1] - rect[0])), int(np.linalg.norm(rect[3] - rect[2])))
                    height = max(int(np.linalg.norm(rect[2] - rect[1])), int(np.linalg.norm(rect[3] - rect[0])))
                    
                    # Create destination points
                    dst = np.array([
                        [0, 0],
                        [width - 1, 0],
                        [width - 1, height - 1],
                        [0, height - 1]
                    ], dtype="float32")
                    
                    # Get perspective transform
                    M = cv2.getPerspectiveTransform(rect, dst)
                    
                    # Apply perspective transform
                    warped = cv2.warpPerspective(frame, M, (width, height))
                    
                    return warped
            
            # If no document contour found, return the original frame
            return frame
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Document processing failed: {str(e)}")
            return frame
    
    def _order_points(self, pts):
        """Order points in top-left, top-right, bottom-right, bottom-left order."""
        # Initialize a list of coordinates
        rect = np.zeros((4, 2), dtype="float32")
        
        # The top-left point will have the smallest sum
        # The bottom-right point will have the largest sum
        s = pts.sum(axis=1)
        rect[0] = pts[np.argmin(s)]
        rect[2] = pts[np.argmax(s)]
        
        # The top-right point will have the smallest difference
        # The bottom-left point will have the largest difference
        diff = np.diff(pts, axis=1)
        rect[1] = pts[np.argmin(diff)]
        rect[3] = pts[np.argmax(diff)]
        
        return rect
    
    def _extract_text_from_image(self, image_path):
        """Extract text from an image using OCR."""
        console.print(f"[bold blue]Extracting text from image:[/] [bold green]{image_path}[/]")
        
        try:
            # Check if pytesseract is available
            try:
                import pytesseract
            except ImportError:
                console.print("[bold yellow]Warning:[/] pytesseract not installed. Text extraction not available.")
                console.print("[bold blue]To install:[/] pip install pytesseract")
                console.print("[bold blue]Note:[/] You also need to install Tesseract OCR on your system.")
                return False
            
            # Read the image
            image = cv2.imread(image_path)
            
            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply threshold
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            
            # Extract text
            text = pytesseract.image_to_string(thresh)
            
            # Save text to file
            text_file = f"{os.path.splitext(image_path)[0]}_text.txt"
            with open(text_file, 'w') as f:
                f.write(text)
            
            console.print(f"[bold green]Extracted text saved to:[/] [bold]{text_file}[/]")
            console.print("[bold]Extracted Text:[/]")
            console.print(text)
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Text extraction failed: {str(e)}")
            return False
    
    def _analyze_image_content(self, image, image_path):
        """Analyze the content of an image."""
        try:
            # Convert to RGB for analysis
            rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            
            # Calculate color histogram
            hist_r = cv2.calcHist([rgb], [0], None, [256], [0, 256])
            hist_g = cv2.calcHist([rgb], [1], None, [256], [0, 256])
            hist_b = cv2.calcHist([rgb], [2], None, [256], [0, 256])
            
            # Create histogram plot
            plt.figure(figsize=(10, 6))
            plt.plot(hist_r, color='red', label='Red')
            plt.plot(hist_g, color='green', label='Green')
            plt.plot(hist_b, color='blue', label='Blue')
            plt.title('Color Histogram')
            plt.xlabel('Pixel Value')
            plt.ylabel('Frequency')
            plt.legend()
            
            # Save histogram
            hist_output = f"{os.path.splitext(image_path)[0]}_histogram.png"
            plt.savefig(hist_output)
            plt.close()
            
            console.print(f"[bold green]Color histogram saved to:[/] [bold]{hist_output}[/]")
            
            # Calculate image statistics
            mean_color = np.mean(rgb, axis=(0, 1))
            std_color = np.std(rgb, axis=(0, 1))
            
            console.print("[bold]Image Statistics:[/]")
            console.print(f"Mean RGB: ({mean_color[0]:.2f}, {mean_color[1]:.2f}, {mean_color[2]:.2f})")
            console.print(f"Std RGB: ({std_color[0]:.2f}, {std_color[1]:.2f}, {std_color[2]:.2f})")
            
            # Detect edges
            edges = cv2.Canny(cv2.cvtColor(image, cv2.COLOR_BGR2GRAY), 100, 200)
            
            # Save edge detection
            edge_output = f"{os.path.splitext(image_path)[0]}_edges.png"
            cv2.imwrite(edge_output, edges)
            
            console.print(f"[bold green]Edge detection saved to:[/] [bold]{edge_output}[/]")
            
            return True
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Image content analysis failed: {str(e)}")
            return False
    
    def _error_level_analysis(self, image_path):
        """Perform Error Level Analysis (ELA) on an image."""
        try:
            # Open the image with PIL
            original = PIL.Image.open(image_path)
            
            # Save with a specific quality
            temp_file = f"{os.path.splitext(image_path)[0]}_temp.jpg"
            original.save(temp_file, 'JPEG', quality=95)
            
            # Open the saved image
            saved = PIL.Image.open(temp_file)
            
            # Calculate the difference
            diff = PIL.ImageChops.difference(original, saved)
            
            # Amplify the difference
            diff = PIL.ImageEnhance.Brightness(diff).enhance(20.0)
            
            # Convert to numpy array
            ela_image = np.array(diff)
            
            # Remove temporary file
            os.remove(temp_file)
            
            return ela_image
            
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Error Level Analysis failed: {str(e)}")
            return None
    
    def _analyze_noise(self, gray_image):
        """Analyze noise patterns in an image."""
        try:
            # Apply median blur to remove noise
            denoised = cv2.medianBlur(gray_image, 5)
            
            # Calculate noise as the difference between original and denoised
            noise = cv2.absdiff(gray_image, denoised)
            
            # Calculate noise statistics
            mean_noise = np.mean(noise)
            std_noise = np.std(noise)
            
            # Check for inconsistencies in noise
            if std_noise < 5:
                return "Low noise variance, possibly manipulated or heavily processed"
            elif mean_noise > 20:
                return "High noise level, possibly low quality or heavily compressed"
            else:
                return "Normal noise pattern, no obvious manipulation detected"
            
        except Exception as e:
            return f"Noise analysis failed: {str(e)}"
    
    def _analyze_metadata_consistency(self, metadata):
        """Analyze metadata for inconsistencies."""
        if not metadata:
            return "No metadata available for analysis"
        
        inconsistencies = []
        
        # Check for software traces
        if 'Software' in metadata and any(editor in metadata['Software'] for editor in ['Photoshop', 'GIMP', 'Lightroom']):
            inconsistencies.append(f"Image edited with {metadata['Software']}")
        
        # Check for modification time vs. creation time
        if 'Creation Time' in metadata and 'Modification Time' in metadata:
            creation = datetime.strptime(metadata['Creation Time'], '%Y-%m-%d %H:%M:%S')
            modification = datetime.strptime(metadata['Modification Time'], '%Y-%m-%d %H:%M:%S')
            
            if modification > creation:
                time_diff = modification - creation
                if time_diff.total_seconds() > 60:  # More than a minute difference
                    inconsistencies.append(f"File modified {time_diff} after creation")
        
        # Check for missing essential EXIF data in digital camera images
        if 'Image Format' in metadata and metadata['Image Format'] in ['JPEG', 'JPG']:
            essential_tags = ['Make', 'Model', 'DateTime']
            missing_tags = [tag for tag in essential_tags if tag not in metadata]
            
            if missing_tags:
                inconsistencies.append(f"Missing essential EXIF tags: {', '.join(missing_tags)}")
        
        if inconsistencies:
            return "Potential inconsistencies detected: " + "; ".join(inconsistencies)
        else:
            return "No metadata inconsistencies detected"
