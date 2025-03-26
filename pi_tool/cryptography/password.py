"""
Password Analyzer module for the Ultimate PI Tool.

This module provides functionality for password strength analysis,
generation, and management.
"""

import os
import sys
import re
import string
import random
import math
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

class PasswordAnalyzer:
    """Password Analyzer class for strength analysis and generation."""
    
    def __init__(self):
        """Initialize the Password Analyzer module."""
        pass
    
    def analyze_strength(self, password):
        """Analyze the strength of a password."""
        console.print(f"[bold blue]Analyzing password strength[/]")
        
        # Create table for results
        table = Table(title="Password Strength Analysis")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Score", style="yellow")
        
        # Calculate metrics
        length = len(password)
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_symbols = bool(re.search(r'[^a-zA-Z0-9\s]', password))
        
        # Count character types
        char_types = sum([has_lowercase, has_uppercase, has_digits, has_symbols])
        
        # Check for common patterns
        has_sequential_chars = bool(re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)', password.lower()))
        has_repeated_chars = bool(re.search(r'(.)\1{2,}', password))
        has_common_words = self._check_common_words(password)
        
        # Calculate entropy
        entropy = self._calculate_entropy(password)
        
        # Calculate overall score (0-100)
        score = 0
        
        # Length score (0-40)
        length_score = min(40, length * 2)
        score += length_score
        
        # Character types score (0-20)
        char_types_score = char_types * 5
        score += char_types_score
        
        # Patterns penalty (0-20)
        patterns_penalty = 0
        if has_sequential_chars:
            patterns_penalty += 7
        if has_repeated_chars:
            patterns_penalty += 7
        if has_common_words:
            patterns_penalty += 6
        
        score -= patterns_penalty
        
        # Entropy bonus (0-20)
        entropy_score = min(20, int(entropy / 3))
        score += entropy_score
        
        # Ensure score is within 0-100
        score = max(0, min(100, score))
        
        # Determine strength category
        if score < 20:
            strength = "Very Weak"
            strength_color = "red"
        elif score < 40:
            strength = "Weak"
            strength_color = "red"
        elif score < 60:
            strength = "Moderate"
            strength_color = "yellow"
        elif score < 80:
            strength = "Strong"
            strength_color = "green"
        else:
            strength = "Very Strong"
            strength_color = "green"
        
        # Add rows to table
        table.add_row("Length", str(length), str(length_score))
        table.add_row("Lowercase Letters", "Yes" if has_lowercase else "No", "5" if has_lowercase else "0")
        table.add_row("Uppercase Letters", "Yes" if has_uppercase else "No", "5" if has_uppercase else "0")
        table.add_row("Digits", "Yes" if has_digits else "No", "5" if has_digits else "0")
        table.add_row("Special Characters", "Yes" if has_symbols else "No", "5" if has_symbols else "0")
        table.add_row("Sequential Characters", "Yes" if has_sequential_chars else "No", "-7" if has_sequential_chars else "0")
        table.add_row("Repeated Characters", "Yes" if has_repeated_chars else "No", "-7" if has_repeated_chars else "0")
        table.add_row("Common Words", "Yes" if has_common_words else "No", "-6" if has_common_words else "0")
        table.add_row("Entropy", f"{entropy:.2f} bits", str(entropy_score))
        table.add_row("Total Score", f"{score}/100", f"[{strength_color}]{strength}[/{strength_color}]")
        
        # Display results
        console.print(table)
        
        # Provide recommendations
        console.print("[bold blue]Recommendations:[/]")
        if length < 12:
            console.print("- [yellow]Increase password length to at least 12 characters[/]")
        if not has_lowercase:
            console.print("- [yellow]Add lowercase letters[/]")
        if not has_uppercase:
            console.print("- [yellow]Add uppercase letters[/]")
        if not has_digits:
            console.print("- [yellow]Add digits[/]")
        if not has_symbols:
            console.print("- [yellow]Add special characters[/]")
        if has_sequential_chars:
            console.print("- [yellow]Avoid sequential characters (e.g., 'abc', '123')[/]")
        if has_repeated_chars:
            console.print("- [yellow]Avoid repeated characters (e.g., 'aaa', '111')[/]")
        if has_common_words:
            console.print("- [yellow]Avoid common words and phrases[/]")
        
        # Estimated time to crack
        crack_time = self._estimate_crack_time(entropy)
        console.print(f"[bold blue]Estimated time to crack:[/] {crack_time}")
        
        return {
            "score": score,
            "strength": strength,
            "entropy": entropy,
            "crack_time": crack_time
        }
    
    def generate_password(self, length=16, complexity="high"):
        """Generate a strong random password."""
        console.print(f"[bold blue]Generating {complexity} complexity password of length {length}[/]")
        
        try:
            # Define character sets based on complexity
            lowercase = string.ascii_lowercase
            uppercase = string.ascii_uppercase
            digits = string.digits
            symbols = string.punctuation
            
            if complexity.lower() == "low":
                # Only lowercase and digits
                chars = lowercase + digits
                min_lowercase = 1
                min_uppercase = 0
                min_digits = 1
                min_symbols = 0
            elif complexity.lower() == "medium":
                # Lowercase, uppercase, and digits
                chars = lowercase + uppercase + digits
                min_lowercase = 1
                min_uppercase = 1
                min_digits = 1
                min_symbols = 0
            else:  # high
                # All character types
                chars = lowercase + uppercase + digits + symbols
                min_lowercase = 1
                min_uppercase = 1
                min_digits = 1
                min_symbols = 1
            
            # Ensure minimum requirements
            password = []
            
            # Add required character types
            if min_lowercase > 0:
                password.extend(random.sample(lowercase, min_lowercase))
            if min_uppercase > 0:
                password.extend(random.sample(uppercase, min_uppercase))
            if min_digits > 0:
                password.extend(random.sample(digits, min_digits))
            if min_symbols > 0:
                password.extend(random.sample(symbols, min_symbols))
            
            # Fill the rest with random characters
            remaining_length = length - len(password)
            if remaining_length > 0:
                password.extend(random.choices(chars, k=remaining_length))
            
            # Shuffle the password
            random.shuffle(password)
            
            # Convert to string
            password_str = ''.join(password)
            
            # Analyze the generated password
            console.print(f"[bold green]Generated Password:[/] {password_str}")
            self.analyze_strength(password_str)
            
            return password_str
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def generate_passphrase(self, num_words=4, separator=" ", capitalize=False):
        """Generate a memorable passphrase from random words."""
        console.print(f"[bold blue]Generating passphrase with {num_words} words[/]")
        
        try:
            # Load word list
            word_list = self._get_word_list()
            
            if not word_list:
                console.print(f"[bold red]Error:[/] Word list not available")
                return None
            
            # Select random words
            words = random.sample(word_list, num_words)
            
            # Apply capitalization if requested
            if capitalize:
                words = [word.capitalize() for word in words]
            
            # Join with separator
            passphrase = separator.join(words)
            
            # Analyze the generated passphrase
            console.print(f"[bold green]Generated Passphrase:[/] {passphrase}")
            self.analyze_strength(passphrase)
            
            return passphrase
            
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def _calculate_entropy(self, password):
        """Calculate the entropy of a password in bits."""
        # Count character set size
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_symbols = bool(re.search(r'[^a-zA-Z0-9\s]', password))
        
        charset_size = 0
        if has_lowercase:
            charset_size += 26
        if has_uppercase:
            charset_size += 26
        if has_digits:
            charset_size += 10
        if has_symbols:
            charset_size += 33  # Approximate number of special characters
        
        # Calculate entropy
        if charset_size > 0:
            entropy = math.log2(charset_size) * len(password)
        else:
            entropy = 0
        
        return entropy
    
    def _estimate_crack_time(self, entropy):
        """Estimate the time it would take to crack a password with given entropy."""
        # Assume 10 billion guesses per second (high-end hardware)
        guesses_per_second = 10_000_000_000
        
        # Calculate number of guesses needed (2^entropy)
        guesses_needed = 2 ** entropy
        
        # Calculate time in seconds
        seconds = guesses_needed / guesses_per_second
        
        # Convert to human-readable format
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        elif seconds < 31536000 * 100:
            return f"{seconds/31536000:.2f} years"
        else:
            return "centuries"
    
    def _check_common_words(self, password):
        """Check if the password contains common words."""
        # List of common words to check
        common_words = [
            "password", "123456", "qwerty", "admin", "welcome",
            "login", "abc123", "letmein", "monkey", "dragon",
            "baseball", "football", "shadow", "master", "superman",
            "trustno1", "sunshine", "iloveyou", "princess", "admin123"
        ]
        
        # Convert to lowercase for comparison
        password_lower = password.lower()
        
        # Check if any common word is in the password
        for word in common_words:
            if word in password_lower:
                return True
        
        return False
    
    def _get_word_list(self):
        """Get a list of words for passphrase generation."""
        # Simple word list for demonstration
        # In a real implementation, this would load from a file
        return [
            "apple", "banana", "orange", "grape", "melon",
            "house", "table", "chair", "window", "door",
            "river", "mountain", "forest", "desert", "ocean",
            "happy", "sunny", "cloudy", "rainy", "windy",
            "quick", "slow", "strong", "weak", "brave",
            "red", "blue", "green", "yellow", "purple",
            "dog", "cat", "bird", "fish", "horse",
            "book", "paper", "pencil", "phone", "computer",
            "music", "movie", "game", "sport", "dance",
            "car", "train", "plane", "boat", "bicycle"
        ]
