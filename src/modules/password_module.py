#!/usr/bin/env python3
"""
Password cracking module using hashcat and John the Ripper.
Provides functionality to crack various hash types using external tools.
"""

import subprocess
import os
import re
import tempfile
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PasswordCracker:
    """Password cracking class supporting multiple hash types and tools."""
    
    def __init__(self):
        self.hashcat_available = self._check_tool_availability('hashcat')
        self.john_available = self._check_tool_availability('john')
        self.default_wordlists = self._get_default_wordlists()
        
    def _check_tool_availability(self, tool_name: str) -> bool:
        """Check if a password cracking tool is available."""
        try:
            result = subprocess.run([tool_name, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _get_default_wordlists(self) -> List[str]:
        """Get list of available wordlists."""
        wordlists = []
        common_paths = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/dict/words',
            '/usr/share/wordlists/passwords.txt',
            './wordlists/common.txt'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                wordlists.append(path)
        
        return wordlists
    
    def _detect_hash_type(self, hash_value: str) -> Optional[Tuple[str, int]]:
        """
        Detect hash type based on format and length.
        Returns (hash_type, hashcat_mode) or None if unknown.
        """
        hash_value = hash_value.strip()
        
        # MD5 (32 hex chars)
        if re.match(r'^[a-fA-F0-9]{32}$', hash_value):
            return ('MD5', 0)
        
        # SHA1 (40 hex chars)
        if re.match(r'^[a-fA-F0-9]{40}$', hash_value):
            return ('SHA1', 100)
        
        # SHA256 (64 hex chars)
        if re.match(r'^[a-fA-F0-9]{64}$', hash_value):
            return ('SHA256', 1400)
        
        # SHA512 (128 hex chars)
        if re.match(r'^[a-fA-F0-9]{128}$', hash_value):
            return ('SHA512', 1700)
        
        # NTLM (32 hex chars, specific format)
        if re.match(r'^[a-fA-F0-9]{32}$', hash_value):
            return ('NTLM', 1000)
        
        # MD5crypt (starts with $1$)
        if hash_value.startswith('$1$'):
            return ('MD5crypt', 500)
        
        # SHA256crypt (starts with $5$)
        if hash_value.startswith('$5$'):
            return ('SHA256crypt', 7400)
        
        # SHA512crypt (starts with $6$)
        if hash_value.startswith('$6$'):
            return ('SHA512crypt', 1800)
        
        # bcrypt (starts with $2a$, $2b$, $2x$, $2y$)
        if hash_value.startswith(('$2a$', '$2b$', '$2x$', '$2y$')):
            return ('bcrypt', 3200)
        
        return None
    
    def _validate_wordlist(self, wordlist_path: str) -> bool:
        """Validate that the wordlist file exists and is readable."""
        if not os.path.exists(wordlist_path):
            logger.error(f"Wordlist file not found: {wordlist_path}")
            return False
        
        if not os.access(wordlist_path, os.R_OK):
            logger.error(f"Wordlist file not readable: {wordlist_path}")
            return False
        
        # Check if file has content
        if os.path.getsize(wordlist_path) == 0:
            logger.error(f"Wordlist file is empty: {wordlist_path}")
            return False
        
        return True
    
    def _create_temp_hash_file(self, hash_value: str) -> str:
        """Create a temporary file containing the hash."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash')
        temp_file.write(hash_value + '\n')
        temp_file.close()
        return temp_file.name
    
    def _cleanup_temp_file(self, file_path: str):
        """Clean up temporary files."""
        try:
            os.unlink(file_path)
        except OSError:
            pass
    
    def _crack_with_hashcat(self, hash_value: str, wordlist_path: str, hash_type: str, hashcat_mode: int) -> Dict:
        """Attempt to crack hash using hashcat."""
        try:
            # Create temporary hash file
            hash_file = self._create_temp_hash_file(hash_value)
            
            # Prepare hashcat command
            cmd = [
                'hashcat',
                '-m', str(hashcat_mode),  # Hash type
                '-a', '0',               # Attack mode: straight (wordlist)
                '--quiet',               # Suppress unnecessary output
                '--force',               # Ignore warnings
                hash_file,
                wordlist_path
            ]
            
            # Execute hashcat
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Get results using hashcat --show
            show_cmd = ['hashcat', '-m', str(hashcat_mode), '--show', hash_file]
            show_result = subprocess.run(show_cmd, capture_output=True, text=True, timeout=30)
            
            # Parse results
            cracked_password = None
            if show_result.returncode == 0 and show_result.stdout.strip():
                # Format: hash:password
                parts = show_result.stdout.strip().split(':')
                if len(parts) >= 2:
                    cracked_password = parts[1]
            
            # Cleanup
            self._cleanup_temp_file(hash_file)
            
            return {
                'tool': 'hashcat',
                'hash_type': hash_type,
                'hashcat_mode': hashcat_mode,
                'cracked': cracked_password is not None,
                'password': cracked_password,
                'stdout': show_result.stdout,
                'stderr': show_result.stderr,
                'return_code': show_result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                'tool': 'hashcat',
                'error': 'Timeout exceeded (300 seconds)',
                'cracked': False,
                'password': None
            }
        except Exception as e:
            return {
                'tool': 'hashcat',
                'error': str(e),
                'cracked': False,
                'password': None
            }
    
    def _crack_with_john(self, hash_value: str, wordlist_path: str, hash_type: str) -> Dict:
        """Attempt to crack hash using John the Ripper."""
        try:
            # Create temporary hash file
            hash_file = self._create_temp_hash_file(hash_value)
            
            # Prepare John command
            cmd = [
                'john',
                '--wordlist=' + wordlist_path,
                '--format=' + hash_type.lower(),
                hash_file
            ]
            
            # Execute John
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Show results
            show_cmd = ['john', '--show', '--format=' + hash_type.lower(), hash_file]
            show_result = subprocess.run(show_cmd, capture_output=True, text=True, timeout=30)
            
            # Parse results
            cracked_password = None
            if show_result.returncode == 0 and show_result.stdout.strip():
                # Format: hash:password
                parts = show_result.stdout.strip().split(':')
                if len(parts) >= 2:
                    cracked_password = parts[1]
            
            # Cleanup
            self._cleanup_temp_file(hash_file)
            
            return {
                'tool': 'john',
                'hash_type': hash_type,
                'cracked': cracked_password is not None,
                'password': cracked_password,
                'stdout': show_result.stdout,
                'stderr': show_result.stderr,
                'return_code': show_result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                'tool': 'john',
                'error': 'Timeout exceeded (300 seconds)',
                'cracked': False,
                'password': None
            }
        except Exception as e:
            return {
                'tool': 'john',
                'error': str(e),
                'cracked': False,
                'password': None
            }
    
    def crack_password(self, hash_value: str, wordlist_path: str = None) -> Dict:
        """
        Main password cracking function.
        
        Args:
            hash_value: The hash to crack
            wordlist_path: Path to wordlist file (optional)
            
        Returns:
            Dictionary with cracking results
        """
        logger.info(f"Starting password cracking for hash: {hash_value[:20]}...")
        
        # Validate hash
        if not hash_value or not hash_value.strip():
            return {
                'error': 'Empty hash value provided',
                'cracked': False,
                'password': None
            }
        
        hash_value = hash_value.strip()
        
        # Detect hash type
        hash_info = self._detect_hash_type(hash_value)
        if not hash_info:
            return {
                'error': 'Unable to detect hash type. Supported formats: MD5, SHA1, SHA256, SHA512, NTLM, MD5crypt, SHA256crypt, SHA512crypt, bcrypt',
                'cracked': False,
                'password': None
            }
        
        hash_type, hashcat_mode = hash_info
        logger.info(f"Detected hash type: {hash_type}")
        
        # Handle wordlist
        if not wordlist_path:
            if self.default_wordlists:
                wordlist_path = self.default_wordlists[0]
                logger.info(f"Using default wordlist: {wordlist_path}")
            else:
                return {
                    'error': 'No wordlist provided and no default wordlists found. Please specify a wordlist path.',
                    'cracked': False,
                    'password': None
                }
        
        # Validate wordlist
        if not self._validate_wordlist(wordlist_path):
            return {
                'error': f'Invalid wordlist: {wordlist_path}',
                'cracked': False,
                'password': None
            }
        
        results = []
        
        # Try hashcat first if available
        if self.hashcat_available:
            logger.info("Attempting to crack with hashcat...")
            result = self._crack_with_hashcat(hash_value, wordlist_path, hash_type, hashcat_mode)
            results.append(result)
            
            if result.get('cracked'):
                logger.info("Password successfully cracked with hashcat!")
                return {
                    'success': True,
                    'tool': 'hashcat',
                    'hash_type': hash_type,
                    'hash_value': hash_value,
                    'wordlist': wordlist_path,
                    'cracked_password': result['password'],
                    'execution_time': 'N/A',
                    'attempts': 'N/A'
                }
        
        # Try John the Ripper if hashcat failed or unavailable
        if self.john_available:
            logger.info("Attempting to crack with John the Ripper...")
            result = self._crack_with_john(hash_value, wordlist_path, hash_type)
            results.append(result)
            
            if result.get('cracked'):
                logger.info("Password successfully cracked with John the Ripper!")
                return {
                    'success': True,
                    'tool': 'john',
                    'hash_type': hash_type,
                    'hash_value': hash_value,
                    'wordlist': wordlist_path,
                    'cracked_password': result['password'],
                    'execution_time': 'N/A',
                    'attempts': 'N/A'
                }
        
        # If we reach here, cracking failed
        return {
            'success': False,
            'error': 'Password not cracked with available tools',
            'hash_type': hash_type,
            'hash_value': hash_value,
            'wordlist': wordlist_path,
            'cracked_password': None,
            'results': results
        }

def password_crack(hash_value: str, wordlist_path: str = None) -> Dict:
    """
    Tool function for password cracking.
    
    Args:
        hash_value: The hash to crack
        wordlist_path: Path to wordlist file (optional)
        
    Returns:
        Dictionary with cracking results
    """
    cracker = PasswordCracker()
    return cracker.crack_password(hash_value, wordlist_path)

# Test function for standalone testing
if __name__ == "__main__":
    # Test with sample hashes
    test_hashes = [
        "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5 of 'password'
        "e99a18c428cb38d5f260853678922e03",  # MD5 of 'abc123'
        "$1$salt$sJq7q5QqQqQqQqQqQqQqQ.",   # MD5crypt
    ]
    
    cracker = PasswordCracker()
    
    print("=== Password Cracking Module Test ===")
    print(f"Hashcat available: {cracker.hashcat_available}")
    print(f"John available: {cracker.john_available}")
    print(f"Default wordlists: {cracker.default_wordlists}")
    print()
    
    for test_hash in test_hashes:
        print(f"Testing hash: {test_hash}")
        result = cracker.crack_password(test_hash)
        print(f"Result: {result}")
        print("-" * 50)
