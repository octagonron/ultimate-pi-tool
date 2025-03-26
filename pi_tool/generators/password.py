"""
Password Generator module for the Ultimate PI Tool.

This module provides functionality for generating secure passwords with
various complexity levels and patterns.
"""

import os
import sys
import json
import random
import string
import math
from rich.console import Console
from rich.table import Table
import zxcvbn

console = Console()

class PasswordGenerator:
    """Password Generator class for creating secure passwords."""
    
    def __init__(self):
        """Initialize the Password Generator module."""
        self.lowercase_chars = string.ascii_lowercase
        self.uppercase_chars = string.ascii_uppercase
        self.digit_chars = string.digits
        self.special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
        self.ambiguous_chars = "Il1O0"
        
        # Common password patterns
        self.patterns = {
            "alternating": self._generate_alternating,
            "blocks": self._generate_blocks,
            "memorable": self._generate_memorable,
            "pronounceable": self._generate_pronounceable,
            "random": self._generate_random
        }
    
    def generate(self, length=16, count=10, include_uppercase=True, include_digits=True, 
                include_special=True, exclude_ambiguous=False, exclude_similar=False,
                pattern=None):
        """Generate secure passwords."""
        console.print(f"[bold blue]Generating {count} passwords (length: {length})[/]")
        
        # Validate inputs
        if length < 8:
            console.print("[bold yellow]Warning:[/] Password length less than 8 is not recommended")
        
        if not any([include_uppercase, include_digits, include_special]):
            console.print("[bold yellow]Warning:[/] Including only lowercase letters reduces password strength")
        
        # Generate passwords
        passwords = []
        
        # Use specified pattern if provided
        if pattern and pattern in self.patterns:
            generator_func = self.patterns[pattern]
            for _ in range(count * 2):  # Generate more than needed to account for duplicates
                password = generator_func(
                    length=length,
                    include_uppercase=include_uppercase,
                    include_digits=include_digits,
                    include_special=include_special,
                    exclude_ambiguous=exclude_ambiguous,
                    exclude_similar=exclude_similar
                )
                passwords.append(password)
        else:
            # Use random pattern if none specified
            for _ in range(count * 2):  # Generate more than needed to account for duplicates
                # Choose a random pattern
                pattern_name = random.choice(list(self.patterns.keys()))
                generator_func = self.patterns[pattern_name]
                
                password = generator_func(
                    length=length,
                    include_uppercase=include_uppercase,
                    include_digits=include_digits,
                    include_special=include_special,
                    exclude_ambiguous=exclude_ambiguous,
                    exclude_similar=exclude_similar
                )
                passwords.append(password)
        
        # Remove duplicates and limit to count
        passwords = list(set(passwords))
        passwords = random.sample(passwords, min(count, len(passwords)))
        
        # Analyze and display results
        self._analyze_passwords(passwords)
        
        return passwords
    
    def generate_from_phrase(self, phrase, count=10, separator="_", capitalize=True, 
                           include_digits=True, include_special=True):
        """Generate passwords based on a phrase."""
        console.print(f"[bold blue]Generating passwords from phrase[/]")
        
        if not phrase:
            console.print("[bold red]Error:[/] Phrase must be provided")
            return []
        
        # Split phrase into words
        words = phrase.split()
        
        if len(words) < 2:
            console.print("[bold yellow]Warning:[/] Phrase should contain multiple words for better results")
        
        # Generate passwords
        passwords = []
        
        # Generate initial password from first letters
        for _ in range(count * 2):  # Generate more than needed to account for duplicates
            # Get first letters
            first_letters = [word[0] for word in words if word]
            
            # Apply capitalization
            if capitalize:
                first_letters = [letter.upper() if random.random() < 0.5 else letter.lower() 
                               for letter in first_letters]
            else:
                first_letters = [letter.lower() for letter in first_letters]
            
            # Add digits if requested
            if include_digits:
                for i in range(random.randint(1, 3)):
                    position = random.randint(0, len(first_letters))
                    first_letters.insert(position, random.choice(string.digits))
            
            # Add special chars if requested
            if include_special:
                for i in range(random.randint(1, 2)):
                    position = random.randint(0, len(first_letters))
                    first_letters.insert(position, random.choice(self.special_chars))
            
            # Join with separator
            password = separator.join(first_letters)
            
            passwords.append(password)
        
        # Generate additional passwords from word combinations
        for _ in range(count * 2):  # Generate more than needed to account for duplicates
            # Select random words
            selected_words = random.sample(words, min(random.randint(2, 4), len(words)))
            
            # Apply transformations
            transformed_words = []
            for word in selected_words:
                # Capitalize
                if capitalize and random.random() < 0.5:
                    word = word.capitalize()
                else:
                    word = word.lower()
                
                # Replace letters with digits or special chars
                if include_digits or include_special:
                    word_chars = list(word)
                    for i in range(len(word_chars)):
                        if include_digits and word_chars[i].lower() == 'o' and random.random() < 0.5:
                            word_chars[i] = '0'
                        elif include_digits and word_chars[i].lower() == 'i' and random.random() < 0.5:
                            word_chars[i] = '1'
                        elif include_digits and word_chars[i].lower() == 'e' and random.random() < 0.5:
                            word_chars[i] = '3'
                        elif include_digits and word_chars[i].lower() == 'a' and random.random() < 0.5:
                            word_chars[i] = '4'
                        elif include_digits and word_chars[i].lower() == 's' and random.random() < 0.5:
                            word_chars[i] = '5'
                        elif include_special and word_chars[i].lower() == 'a' and random.random() < 0.5:
                            word_chars[i] = '@'
                        elif include_special and word_chars[i].lower() == 's' and random.random() < 0.5:
                            word_chars[i] = '$'
                    
                    word = ''.join(word_chars)
                
                transformed_words.append(word)
            
            # Join with separator
            password = separator.join(transformed_words)
            
            # Add random digits at the end
            if include_digits:
                password += str(random.randint(10, 999))
            
            passwords.append(password)
        
        # Remove duplicates and limit to count
        passwords = list(set(passwords))
        passwords = random.sample(passwords, min(count, len(passwords)))
        
        # Analyze and display results
        self._analyze_passwords(passwords)
        
        return passwords
    
    def generate_passphrases(self, word_count=4, count=10, separator=" ", capitalize=True):
        """Generate memorable passphrases using random words."""
        console.print(f"[bold blue]Generating {count} passphrases (word count: {word_count})[/]")
        
        # Load word list
        words = self._load_word_list()
        
        if not words:
            console.print("[bold red]Error:[/] Word list not available")
            return []
        
        # Generate passphrases
        passphrases = []
        
        for _ in range(count * 2):  # Generate more than needed to account for duplicates
            # Select random words
            selected_words = random.sample(words, word_count)
            
            # Apply capitalization
            if capitalize:
                selected_words = [word.capitalize() for word in selected_words]
            
            # Join with separator
            passphrase = separator.join(selected_words)
            
            passphrases.append(passphrase)
        
        # Remove duplicates and limit to count
        passphrases = list(set(passphrases))
        passphrases = random.sample(passphrases, min(count, len(passphrases)))
        
        # Analyze and display results
        self._analyze_passwords(passphrases)
        
        return passphrases
    
    def analyze_password(self, password):
        """Analyze the strength of a password."""
        console.print(f"[bold blue]Analyzing password strength[/]")
        
        if not password:
            console.print("[bold red]Error:[/] Password must be provided")
            return None
        
        # Use zxcvbn for password strength analysis
        result = zxcvbn.zxcvbn(password)
        
        # Calculate entropy
        charset_size = 0
        if any(c in string.ascii_lowercase for c in password):
            charset_size += 26
        if any(c in string.ascii_uppercase for c in password):
            charset_size += 26
        if any(c in string.digits for c in password):
            charset_size += 10
        if any(c in self.special_chars for c in password):
            charset_size += len(self.special_chars)
        
        entropy = math.log2(charset_size ** len(password)) if charset_size > 0 else 0
        
        # Create analysis report
        analysis = {
            "password": password,
            "length": len(password),
            "entropy": entropy,
            "score": result["score"],  # 0-4, with 4 being the strongest
            "crack_time_seconds": result["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"],
            "crack_time_display": result["crack_times_display"]["offline_fast_hashing_1e10_per_second"],
            "feedback": result["feedback"],
            "patterns": result["sequence"]
        }
        
        # Display analysis
        self._display_password_analysis(analysis)
        
        return analysis
    
    def save_to_file(self, passwords, output_file):
        """Save generated passwords to a file."""
        console.print(f"[bold blue]Saving {len(passwords)} passwords to:[/] [bold green]{output_file}[/]")
        
        try:
            with open(output_file, 'w') as f:
                for password in passwords:
                    f.write(f"{password}\n")
            
            console.print(f"[bold green]Passwords saved successfully![/]")
            return True
            
        except Exception as e:
            console.print(f"[bold red]Error saving passwords:[/] {str(e)}")
            return False
    
    def _generate_random(self, length=16, include_uppercase=True, include_digits=True, 
                       include_special=True, exclude_ambiguous=False, exclude_similar=False):
        """Generate a completely random password."""
        # Define character set
        chars = self.lowercase_chars
        
        if include_uppercase:
            chars += self.uppercase_chars
        
        if include_digits:
            chars += self.digit_chars
        
        if include_special:
            chars += self.special_chars
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            for c in self.ambiguous_chars:
                chars = chars.replace(c, "")
        
        # Remove similar characters if requested
        if exclude_similar:
            for c in "iIlL1oO0":
                chars = chars.replace(c, "")
        
        # Generate password
        password = ''.join(random.choice(chars) for _ in range(length))
        
        # Ensure all required character types are included
        if include_uppercase and not any(c in self.uppercase_chars for c in password):
            password = self._replace_random_char(password, self.uppercase_chars)
        
        if include_digits and not any(c in self.digit_chars for c in password):
            password = self._replace_random_char(password, self.digit_chars)
        
        if include_special and not any(c in self.special_chars for c in password):
            password = self._replace_random_char(password, self.special_chars)
        
        return password
    
    def _generate_alternating(self, length=16, include_uppercase=True, include_digits=True, 
                            include_special=True, exclude_ambiguous=False, exclude_similar=False):
        """Generate a password with alternating character types."""
        # Define character sets
        char_sets = [self.lowercase_chars]
        
        if include_uppercase:
            char_sets.append(self.uppercase_chars)
        
        if include_digits:
            char_sets.append(self.digit_chars)
        
        if include_special:
            char_sets.append(self.special_chars)
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            char_sets = [set.replace(c, "") for set in char_sets for c in self.ambiguous_chars]
        
        # Remove similar characters if requested
        if exclude_similar:
            char_sets = [set.replace(c, "") for set in char_sets for c in "iIlL1oO0"]
        
        # Generate password
        password = ""
        for i in range(length):
            char_set = char_sets[i % len(char_sets)]
            password += random.choice(char_set)
        
        return password
    
    def _generate_blocks(self, length=16, include_uppercase=True, include_digits=True, 
                       include_special=True, exclude_ambiguous=False, exclude_similar=False):
        """Generate a password with blocks of character types."""
        # Define character sets
        char_sets = [self.lowercase_chars]
        
        if include_uppercase:
            char_sets.append(self.uppercase_chars)
        
        if include_digits:
            char_sets.append(self.digit_chars)
        
        if include_special:
            char_sets.append(self.special_chars)
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            char_sets = [set.replace(c, "") for set in char_sets for c in self.ambiguous_chars]
        
        # Remove similar characters if requested
        if exclude_similar:
            char_sets = [set.replace(c, "") for set in char_sets for c in "iIlL1oO0"]
        
        # Shuffle character sets
        random.shuffle(char_sets)
        
        # Calculate block sizes
        block_size = length // len(char_sets)
        remainder = length % len(char_sets)
        
        # Generate password
        password = ""
        for i, char_set in enumerate(char_sets):
            # Add extra character from remainder if needed
            current_block_size = block_size + (1 if i < remainder else 0)
            
            # Generate block
            password += ''.join(random.choice(char_set) for _ in range(current_block_size))
        
        # Shuffle the password to mix the blocks
        password_chars = list(password)
        random.shuffle(password_chars)
        password = ''.join(password_chars)
        
        return password
    
    def _generate_memorable(self, length=16, include_uppercase=True, include_digits=True, 
                          include_special=True, exclude_ambiguous=False, exclude_similar=False):
        """Generate a memorable password with a pattern."""
        # Load word list
        words = self._load_word_list()
        
        if not words:
            # Fall back to random if word list not available
            return self._generate_random(
                length=length,
                include_uppercase=include_uppercase,
                include_digits=include_digits,
                include_special=include_special,
                exclude_ambiguous=exclude_ambiguous,
                exclude_similar=exclude_similar
            )
        
        # Filter words by length
        max_word_length = length - 4  # Leave room for digits and special chars
        suitable_words = [word for word in words if 4 <= len(word) <= max_word_length]
        
        if not suitable_words:
            # Fall back to random if no suitable words
            return self._generate_random(
                length=length,
                include_uppercase=include_uppercase,
                include_digits=include_digits,
                include_special=include_special,
                exclude_ambiguous=exclude_ambiguous,
                exclude_similar=exclude_similar
            )
        
        # Select a random word
        word = random.choice(suitable_words)
        
        # Apply capitalization
        if include_uppercase:
            if random.random() < 0.5:
                word = word.capitalize()
            else:
                # Capitalize a random letter
                i = random.randint(0, len(word) - 1)
                word = word[:i] + word[i].upper() + word[i+1:]
        
        # Add digits if requested
        if include_digits:
            digits = ''.join(random.choice(self.digit_chars) for _ in range(random.randint(2, 4)))
            if random.random() < 0.5:
                word = digits + word
            else:
                word = word + digits
        
        # Add special chars if requested
        if include_special:
            special = ''.join(random.choice(self.special_chars) for _ in range(random.randint(1, 2)))
            if random.random() < 0.5:
                word = special + word
            else:
                word = word + special
        
        # Ensure password meets length requirement
        if len(word) < length:
            # Add random characters to reach desired length
            additional_chars = ''.join(
                random.choice(self.lowercase_chars + 
                             (self.uppercase_chars if include_uppercase else "") + 
                             (self.digit_chars if include_digits else "") + 
                             (self.special_chars if include_special else ""))
                for _ in range(length - len(word))
            )
            if random.random() < 0.5:
                word = word + additional_chars
            else:
                word = additional_chars + word
        elif len(word) > length:
            # Truncate to desired length
            word = word[:length]
        
        return word
    
    def _generate_pronounceable(self, length=16, include_uppercase=True, include_digits=True, 
                              include_special=True, exclude_ambiguous=False, exclude_similar=False):
        """Generate a pronounceable password."""
        # Define consonants and vowels
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels = "aeiou"
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            for c in self.ambiguous_chars:
                consonants = consonants.replace(c, "")
                vowels = vowels.replace(c, "")
        
        # Remove similar characters if requested
        if exclude_similar:
            for c in "iIlL1oO0":
                consonants = consonants.replace(c, "")
                vowels = vowels.replace(c, "")
        
        # Generate pronounceable base
        password = ""
        for i in range(length):
            if i % 2 == 0:
                password += random.choice(consonants)
            else:
                password += random.choice(vowels)
        
        # Apply capitalization
        if include_uppercase:
            password_chars = list(password)
            # Capitalize 1-3 random letters
            for _ in range(random.randint(1, 3)):
                i = random.randint(0, len(password_chars) - 1)
                password_chars[i] = password_chars[i].upper()
            password = ''.join(password_chars)
        
        # Add digits if requested
        if include_digits:
            password_chars = list(password)
            # Replace 1-2 random letters with digits
            for _ in range(random.randint(1, 2)):
                i = random.randint(0, len(password_chars) - 1)
                password_chars[i] = random.choice(self.digit_chars)
            password = ''.join(password_chars)
        
        # Add special chars if requested
        if include_special:
            password_chars = list(password)
            # Replace 1 random letter with special char
            i = random.randint(0, len(password_chars) - 1)
            password_chars[i] = random.choice(self.special_chars)
            password = ''.join(password_chars)
        
        return password
    
    def _replace_random_char(self, text, char_set):
        """Replace a random character in text with a character from char_set."""
        if not text or not char_set:
            return text
        
        # Choose a random position and character
        pos = random.randint(0, len(text) - 1)
        new_char = random.choice(char_set)
        
        # Replace character
        return text[:pos] + new_char + text[pos+1:]
    
    def _load_word_list(self):
        """Load a list of common words for password generation."""
        # Define a small set of common words
        common_words = [
            "apple", "banana", "orange", "grape", "melon", "lemon", "cherry", "peach",
            "house", "table", "chair", "couch", "lamp", "desk", "shelf", "door",
            "water", "fire", "earth", "wind", "light", "dark", "sun", "moon",
            "dog", "cat", "bird", "fish", "lion", "tiger", "bear", "wolf",
            "red", "blue", "green", "yellow", "black", "white", "purple", "orange",
            "happy", "sad", "angry", "calm", "brave", "quiet", "loud", "smart",
            "run", "walk", "jump", "swim", "fly", "climb", "dance", "sing",
            "book", "page", "story", "poem", "novel", "tale", "myth", "legend",
            "king", "queen", "knight", "wizard", "dragon", "giant", "elf", "dwarf",
            "river", "lake", "ocean", "sea", "mountain", "valley", "hill", "plain",
            "spring", "summer", "autumn", "winter", "day", "night", "dawn", "dusk",
            "north", "south", "east", "west", "up", "down", "left", "right",
            "gold", "silver", "bronze", "iron", "steel", "copper", "tin", "lead",
            "bread", "cheese", "meat", "fish", "soup", "salad", "cake", "pie"
        ]
        
        return common_words
    
    def _analyze_passwords(self, passwords):
        """Analyze and display a list of generated passwords."""
        # Create results table
        table = Table(title=f"Generated Passwords ({len(passwords)})")
        table.add_column("Password", style="cyan")
        table.add_column("Length", style="green")
        table.add_column("Strength", style="yellow")
        table.add_column("Crack Time", style="magenta")
        
        for password in passwords:
            # Analyze password
            result = zxcvbn.zxcvbn(password)
            
            # Determine strength label
            score = result["score"]
            strength_labels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
            strength = strength_labels[score]
            
            # Get crack time
            crack_time = result["crack_times_display"]["offline_fast_hashing_1e10_per_second"]
            
            # Add to table
            table.add_row(
                password,
                str(len(password)),
                strength,
                crack_time
            )
        
        console.print(table)
    
    def _display_password_analysis(self, analysis):
        """Display password analysis results."""
        # Create results table
        table = Table(title="Password Analysis")
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="green")
        
        # Add basic information
        table.add_row("Password", analysis["password"])
        table.add_row("Length", str(analysis["length"]))
        table.add_row("Entropy", f"{analysis['entropy']:.2f} bits")
        
        # Determine strength label
        score = analysis["score"]
        strength_labels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
        strength = strength_labels[score]
        
        table.add_row("Strength", strength)
        table.add_row("Crack Time", analysis["crack_time_display"])
        
        # Add feedback
        if analysis["feedback"]["warning"]:
            table.add_row("Warning", analysis["feedback"]["warning"])
        
        if analysis["feedback"]["suggestions"]:
            suggestions = "\n".join(analysis["feedback"]["suggestions"])
            table.add_row("Suggestions", suggestions)
        
        console.print(table)
        
        # Display pattern information
        if analysis["patterns"]:
            pattern_table = Table(title="Password Patterns")
            pattern_table.add_column("Pattern", style="cyan")
            pattern_table.add_column("Token", style="green")
            pattern_table.add_column("Type", style="yellow")
            
            for pattern in analysis["patterns"]:
                pattern_table.add_row(
                    pattern["pattern"],
                    pattern["token"],
                    pattern.get("dictionary_name", "N/A")
                )
            
            console.print(pattern_table)
