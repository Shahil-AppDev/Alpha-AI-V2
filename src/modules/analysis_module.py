#!/usr/bin/env python3
"""
Code analysis module for static security analysis.
Provides vulnerability detection using regex patterns and bandit integration.
"""

import re
import ast
import subprocess
import tempfile
import os
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CodeAnalyzer:
    """Static code analysis class for security vulnerability detection."""
    
    def __init__(self):
        self.bandit_available = self._check_bandit_availability()
        self.vulnerability_patterns = self._initialize_vulnerability_patterns()
        
    def _check_bandit_availability(self) -> bool:
        """Check if bandit is available for Python code analysis."""
        try:
            result = subprocess.run(['bandit', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _initialize_vulnerability_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize regex patterns for common vulnerability detection."""
        return {
            'sql_injection': [
                {
                    'pattern': r'execute\s*\(\s*["\'].*?\%s.*?["\']',
                    'description': 'Potential SQL injection via string formatting',
                    'severity': 'high',
                    'cwe': 'CWE-89'
                },
                {
                    'pattern': r'execute\s*\(\s*["\'].*?\+.*?["\']',
                    'description': 'Potential SQL injection via string concatenation',
                    'severity': 'high',
                    'cwe': 'CWE-89'
                },
                {
                    'pattern': r'query\s*\(\s*["\'].*?\%s.*?["\']',
                    'description': 'Potential SQL injection in database query',
                    'severity': 'high',
                    'cwe': 'CWE-89'
                },
                {
                    'pattern': r'select.*from.*where.*["\'].*?\+.*?["\']',
                    'description': 'Potential SQL injection in SELECT statement',
                    'severity': 'high',
                    'cwe': 'CWE-89'
                }
            ],
            'command_injection': [
                {
                    'pattern': r'os\.system\s*\(\s*["\'].*?\%s.*?["\']',
                    'description': 'Command injection via os.system with string formatting',
                    'severity': 'critical',
                    'cwe': 'CWE-78'
                },
                {
                    'pattern': r'os\.system\s*\(\s*["\'].*?\+.*?["\']',
                    'description': 'Command injection via os.system with concatenation',
                    'severity': 'critical',
                    'cwe': 'CWE-78'
                },
                {
                    'pattern': r'subprocess\.call\s*\(\s*["\'].*?\%s.*?["\']',
                    'description': 'Command injection via subprocess.call',
                    'severity': 'critical',
                    'cwe': 'CWE-78'
                },
                {
                    'pattern': r'subprocess\.run\s*\(\s*["\'].*?\%s.*?["\']',
                    'description': 'Command injection via subprocess.run',
                    'severity': 'critical',
                    'cwe': 'CWE-78'
                },
                {
                    'pattern': r'eval\s*\(\s*["\'].*?\%.*?["\']',
                    'description': 'Code injection via eval with string formatting',
                    'severity': 'critical',
                    'cwe': 'CWE-94'
                }
            ],
            'path_traversal': [
                {
                    'pattern': r'open\s*\(\s*["\'].*?\.\./',
                    'description': 'Potential path traversal in file operations',
                    'severity': 'medium',
                    'cwe': 'CWE-22'
                },
                {
                    'pattern': r'open\s*\(\s*["\'].*?\%s.*?["\']',
                    'description': 'Path traversal via string formatting in file operations',
                    'severity': 'medium',
                    'cwe': 'CWE-22'
                }
            ],
            'hardcoded_secrets': [
                {
                    'pattern': r'(password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']',
                    'description': 'Hardcoded password detected',
                    'severity': 'high',
                    'cwe': 'CWE-798'
                },
                {
                    'pattern': r'(api_key|apikey|secret_key)\s*=\s*["\'][^"\']{16,}["\']',
                    'description': 'Hardcoded API key detected',
                    'severity': 'high',
                    'cwe': 'CWE-798'
                },
                {
                    'pattern': r'(token|auth_token)\s*=\s*["\'][^"\']{16,}["\']',
                    'description': 'Hardcoded authentication token detected',
                    'severity': 'high',
                    'cwe': 'CWE-798'
                }
            ],
            'weak_cryptography': [
                {
                    'pattern': r'md5\s*\(',
                    'description': 'Weak cryptographic hash (MD5) detected',
                    'severity': 'medium',
                    'cwe': 'CWE-327'
                },
                {
                    'pattern': r'sha1\s*\(',
                    'description': 'Weak cryptographic hash (SHA1) detected',
                    'severity': 'medium',
                    'cwe': 'CWE-327'
                },
                {
                    'pattern': r'Crypto\.Cipher\.DES\s*\(',
                    'description': 'Weak encryption algorithm (DES) detected',
                    'severity': 'high',
                    'cwe': 'CWE-327'
                }
            ],
            'insecure_deserialization': [
                {
                    'pattern': r'pickle\.loads?\s*\(',
                    'description': 'Insecure deserialization using pickle',
                    'severity': 'critical',
                    'cwe': 'CWE-502'
                },
                {
                    'pattern': r'marshal\.loads?\s*\(',
                    'description': 'Insecure deserialization using marshal',
                    'severity': 'critical',
                    'cwe': 'CWE-502'
                }
            ],
            'information_disclosure': [
                {
                    'pattern': r'print\s*\(\s*["\'].*?(password|secret|token|key)',
                    'description': 'Potential information disclosure in print statements',
                    'severity': 'low',
                    'cwe': 'CWE-200'
                },
                {
                    'pattern': r'logging\.debug\s*\(\s*["\'].*?(password|secret|token|key)',
                    'description': 'Sensitive information in debug logs',
                    'severity': 'low',
                    'cwe': 'CWE-200'
                }
            ]
        }
    
    def _analyze_with_regex(self, code_snippet: str) -> List[Dict[str, Any]]:
        """Analyze code using regex patterns for vulnerability detection."""
        vulnerabilities = []
        lines = code_snippet.split('\n')
        
        for category, patterns in self.vulnerability_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                description = pattern_info['description']
                severity = pattern_info['severity']
                cwe = pattern_info['cwe']
                
                try:
                    for line_num, line in enumerate(lines, 1):
                        matches = re.finditer(pattern, line, re.IGNORECASE | re.MULTILINE)
                        for match in matches:
                            vulnerabilities.append({
                                'type': category,
                                'severity': severity,
                                'description': description,
                                'line': line_num,
                                'code_snippet': line.strip(),
                                'match': match.group(),
                                'cwe': cwe,
                                'tool': 'regex_analysis'
                            })
                except re.error as e:
                    logger.warning(f"Invalid regex pattern: {pattern} - {e}")
        
        return vulnerabilities
    
    def _analyze_with_bandit(self, code_snippet: str) -> List[Dict[str, Any]]:
        """Analyze Python code using bandit static analysis tool."""
        if not self.bandit_available:
            return []
        
        vulnerabilities = []
        
        try:
            # Create temporary file for bandit analysis
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                temp_file.write(code_snippet)
                temp_file_path = temp_file.name
            
            # Run bandit analysis
            cmd = ['bandit', '-f', 'json', temp_file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Parse bandit results
            if result.stdout:
                try:
                    import json
                    bandit_results = json.loads(result.stdout)
                    
                    for issue in bandit_results.get('results', []):
                        vulnerabilities.append({
                            'type': 'bandit_issue',
                            'severity': self._convert_bandit_severity(issue.get('issue_severity', 'MEDIUM')),
                            'description': issue.get('issue_text', 'Unknown issue'),
                            'line': issue.get('line_number', 0),
                            'code_snippet': issue.get('code', ''),
                            'test_id': issue.get('test_id', ''),
                            'test_name': issue.get('test_name', ''),
                            'cwe': issue.get('cwe_id', 'Unknown'),
                            'tool': 'bandit'
                        })
                except json.JSONDecodeError:
                    logger.warning("Failed to parse bandit JSON output")
            
            # Cleanup
            os.unlink(temp_file_path)
            
        except subprocess.TimeoutExpired:
            logger.error("Bandit analysis timed out")
        except Exception as e:
            logger.error(f"Error running bandit: {e}")
        
        return vulnerabilities
    
    def _convert_bandit_severity(self, bandit_severity: str) -> str:
        """Convert bandit severity levels to standard severity."""
        severity_mapping = {
            'LOW': 'low',
            'MEDIUM': 'medium',
            'HIGH': 'high'
        }
        return severity_mapping.get(bandit_severity.upper(), 'medium')
    
    def _analyze_python_ast(self, code_snippet: str) -> List[Dict[str, Any]]:
        """Analyze Python code using AST for additional vulnerability detection."""
        vulnerabilities = []
        
        try:
            tree = ast.parse(code_snippet)
            
            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        
                        # Check for eval/exec usage
                        if func_name in ['eval', 'exec']:
                            vulnerabilities.append({
                                'type': 'code_injection',
                                'severity': 'critical',
                                'description': f'Dangerous use of {func_name}() function',
                                'line': getattr(node, 'lineno', 0),
                                'code_snippet': f'{func_name}(...)',
                                'cwe': 'CWE-94',
                                'tool': 'ast_analysis'
                            })
                        
                        # Check for dangerous imports
                        elif func_name == '__import__':
                            vulnerabilities.append({
                                'type': 'dangerous_import',
                                'severity': 'medium',
                                'description': 'Dynamic import detected',
                                'line': getattr(node, 'lineno', 0),
                                'code_snippet': '__import__(...)',
                                'cwe': 'CWE-94',
                                'tool': 'ast_analysis'
                            })
                    
                    # Check for dangerous attribute access
                    elif isinstance(node.func, ast.Attribute):
                        if node.func.attr in ['system', 'popen', 'call', 'run']:
                            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                                vulnerabilities.append({
                                    'type': 'command_injection',
                                    'severity': 'critical',
                                    'description': f'Potential command injection via os.{node.func.attr}',
                                    'line': getattr(node, 'lineno', 0),
                                    'code_snippet': f'os.{node.func.attr}(...)',
                                    'cwe': 'CWE-78',
                                    'tool': 'ast_analysis'
                                })
                
        except SyntaxError as e:
            vulnerabilities.append({
                'type': 'syntax_error',
                'severity': 'low',
                'description': f'Syntax error in code: {str(e)}',
                'line': getattr(e, 'lineno', 0),
                'code_snippet': '',
                'cwe': 'CWE-704',
                'tool': 'ast_analysis'
            })
        
        return vulnerabilities
    
    def analyze_code(self, code_snippet: str) -> Dict[str, Any]:
        """
        Main code analysis function.
        
        Args:
            code_snippet: The code to analyze
            
        Returns:
            Dictionary with analysis results
        """
        logger.info("Starting static code analysis...")
        
        if not code_snippet or not code_snippet.strip():
            return {
                'error': 'Empty code snippet provided',
                'vulnerabilities': [],
                'summary': {'total_issues': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            }
        
        vulnerabilities = []
        
        # Perform different types of analysis
        vulnerabilities.extend(self._analyze_with_regex(code_snippet))
        vulnerabilities.extend(self._analyze_with_bandit(code_snippet))
        vulnerabilities.extend(self._analyze_python_ast(code_snippet))
        
        # Remove duplicates and sort by severity
        unique_vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
        sorted_vulnerabilities = sorted(unique_vulnerabilities, key=lambda x: self._severity_rank(x['severity']))
        
        # Generate summary
        summary = self._generate_summary(sorted_vulnerabilities)
        
        return {
            'success': True,
            'vulnerabilities': sorted_vulnerabilities,
            'summary': summary,
            'analysis_tools_used': ['regex_analysis', 'bandit' if self.bandit_available else None, 'ast_analysis'],
            'code_length': len(code_snippet),
            'lines_analyzed': len(code_snippet.split('\n'))
        }
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities based on line and type."""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            key = (vuln.get('line'), vuln.get('type'), vuln.get('description'))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def _severity_rank(self, severity: str) -> int:
        """Assign numerical rank to severity for sorting."""
        severity_ranks = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        return severity_ranks.get(severity.lower(), 4)
    
    def _generate_summary(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Generate summary statistics of vulnerabilities found."""
        summary = {
            'total_issues': len(vulnerabilities),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary

def code_analysis(code_snippet: str, use_llm_fallback: bool = False) -> Dict[str, Any]:
    """
    Tool function for static code analysis.
    
    Args:
        code_snippet: The code to analyze
        use_llm_fallback: Whether to use LLM analysis if regex finds limited results
        
    Returns:
        Dictionary with analysis results
    """
    analyzer = CodeAnalyzer()
    result = analyzer.analyze_code(code_snippet)
    
    # Optional LLM analysis fallback
    if use_llm_fallback and len(result['vulnerabilities']) < 3:
        llm_analysis = _perform_llm_analysis(code_snippet)
        if llm_analysis and llm_analysis.get('vulnerabilities'):
            result['vulnerabilities'].extend(llm_analysis['vulnerabilities'])
            result['llm_analysis_used'] = True
            result['summary'] = analyzer._generate_summary(result['vulnerabilities'])
        else:
            result['llm_analysis_used'] = False
    else:
        result['llm_analysis_used'] = False
    
    return result


def _perform_llm_analysis(code: str) -> Optional[Dict[str, Any]]:
    """
    Perform LLM-based code analysis for complex vulnerabilities.
    This is a placeholder for actual LLM integration.
    """
    try:
        # This would integrate with an actual LLM service
        # For now, return a mock analysis
        analysis_prompt = f"""
        Analyze this code for security vulnerabilities:
        {code}
        
        Identify potential security issues including:
        - Authentication flaws
        - Authorization bypasses
        - Data exposure
        - Business logic vulnerabilities
        - Input validation issues
        
        Return findings in JSON format.
        """
        
        # Mock LLM response - replace with actual LLM call
        mock_llm_response = {
            'vulnerabilities': [
                {
                    'type': 'LLM Detected Issue',
                    'severity': 'medium',
                    'line': 0,
                    'code_snippet': 'Full code analysis',
                    'description': 'LLM analysis suggests reviewing authentication logic',
                    'cwe': 'CWE-287',
                    'tool': 'llm_analysis'
                }
            ]
        }
        
        return mock_llm_response
        
    except Exception as e:
        logger.error(f"LLM analysis failed: {str(e)}")
        return None


def get_tool_info():
    """Return tool information for ToolManager registration."""
    return {
        'name': 'code_analysis',
        'description': 'Analyze code snippets for security vulnerabilities using static analysis',
        'parameters': {
            'code_snippet': {
                'type': 'string',
                'description': 'The code snippet to analyze for vulnerabilities',
                'required': True
            },
            'use_llm_fallback': {
                'type': 'boolean',
                'description': 'Use LLM analysis if regex finds limited results',
                'default': False,
                'required': False
            }
        },
        'return_value': {
            'type': 'dict',
            'description': 'Analysis results with identified vulnerabilities and recommendations'
        }
    }


# Test function for standalone testing
if __name__ == "__main__":
    # Test with vulnerable code snippets
    test_code = '''
import os
import subprocess
import pickle

def vulnerable_function(user_input):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE id = %s" % user_input
    cursor.execute(query)
    
    # Command injection vulnerability
    os.system("ls " + user_input)
    
    # Hardcoded password
    password = "supersecret123"
    
    # Weak cryptography
    import hashlib
    hash_value = hashlib.md5(user_input.encode()).hexdigest()
    
    # Insecure deserialization
    data = pickle.loads(user_input)
    
    # Information disclosure
    print(f"User password: {password}")
    
    return data

# Another vulnerable function
def process_file(filename):
    # Path traversal vulnerability
    with open("/var/www/" + filename, 'r') as f:
        return f.read()
'''
    
    analyzer = CodeAnalyzer()
    
    print("=== Code Analysis Module Test ===")
    print(f"Bandit available: {analyzer.bandit_available}")
    print(f"Vulnerability patterns: {len(analyzer.vulnerability_patterns)} categories")
    print()
    
    result = analyzer.analyze_code(test_code)
    print("Analysis Results:")
    print(f"Total vulnerabilities found: {result['summary']['total_issues']}")
    print(f"Critical: {result['summary']['critical']}")
    print(f"High: {result['summary']['high']}")
    print(f"Medium: {result['summary']['medium']}")
    print(f"Low: {result['summary']['low']}")
    print()
    
    for vuln in result['vulnerabilities'][:5]:  # Show first 5 vulnerabilities
        print(f"[{vuln['severity'].upper()}] {vuln['description']}")
        print(f"  Line {vuln['line']}: {vuln['code_snippet']}")
        print(f"  CWE: {vuln['cwe']}, Tool: {vuln['tool']}")
        print()
