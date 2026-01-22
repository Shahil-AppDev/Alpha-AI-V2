"""
Reverse Engineer Module
======================

This module provides functionality for JavaScript reverse engineering operations
including code analysis, deobfuscation, pattern detection, and AST parsing.
"""

import os
import json
import re
import ast
import logging
import subprocess
from typing import Dict, Optional, List, Tuple, Any
from datetime import datetime
from pathlib import Path
import tempfile

logger = logging.getLogger(__name__)

class JavaScriptReverseEngineer:
    """
    JavaScript reverse engineering class for security analysis purposes.
    
    WARNING: This tool should only be used for authorized security testing
    and code analysis. Unauthorized use is illegal and unethical.
    """
    
    def __init__(self):
        self.supported_patterns = [
            "hex_encoded_strings",
            "base64_encoded_strings", 
            "dynamic_code_execution",
            "string_concatenation_obfuscation",
            "array_index_obfuscation",
            "minification_patterns",
            "eval_usage",
            "function_constructor"
        ]
        
        self.analysis_config = {
            "beautify_code": True,
            "extract_functions": True,
            "extract_variables": True,
            "extract_strings": True,
            "detect_patterns": True,
            "analyze_control_flow": True,
            "generate_report": True
        }
    
    def validate_config(self, config: Dict) -> Tuple[bool, str]:
        """Validate the provided analysis configuration."""
        required_fields = ["code"]
        
        for field in required_fields:
            if field not in config:
                return False, f"Missing required field: {field}"
        
        if not config["code"].strip():
            return False, "JavaScript code cannot be empty"
        
        return True, "Configuration is valid"
    
    def check_dependencies(self) -> Tuple[bool, List[str]]:
        """Check if required dependencies are available."""
        missing_deps = []
        
        try:
            # Check for Node.js (required for JavaScript analysis)
            result = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                missing_deps.append("Node.js")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            missing_deps.append("Node.js")
        
        try:
            # Check if reverse-engineer-tool is available
            tool_path = Path(__file__).parent.parent.parent / "tools" / "reverse-engineer-tool"
            if not tool_path.exists():
                missing_deps.append("reverse-engineer-tool")
            else:
                # Check if dependencies are installed
                package_json = tool_path / "package.json"
                node_modules = tool_path / "node_modules"
                if package_json.exists() and not node_modules.exists():
                    missing_deps.append("reverse-engineer-tool dependencies")
        except Exception as e:
            logger.error(f"Dependency check failed: {str(e)}")
            missing_deps.append("reverse-engineer-tool setup")
        
        return len(missing_deps) == 0, missing_deps
    
    def install_dependencies(self) -> Tuple[bool, str]:
        """Install required dependencies for the reverse engineer tool."""
        try:
            tool_path = Path(__file__).parent.parent.parent / "tools" / "reverse-engineer-tool"
            
            if not tool_path.exists():
                return False, "reverse-engineer-tool not found"
            
            # Install npm dependencies
            result = subprocess.run(
                ["npm", "install"],
                cwd=tool_path,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                logger.info("Dependencies installed successfully")
                return True, "Dependencies installed successfully"
            else:
                logger.error(f"npm install failed: {result.stderr}")
                return False, f"Failed to install dependencies: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            logger.error("Dependency installation timed out")
            return False, "Installation timed out"
        except Exception as e:
            logger.error(f"Dependency installation failed: {str(e)}")
            return False, f"Installation failed: {str(e)}"
    
    def beautify_code(self, code: str) -> Tuple[bool, str]:
        """Beautify and format minified JavaScript code."""
        try:
            tool_path = Path(__file__).parent.parent.parent / "tools" / "reverse-engineer-tool"
            
            # Write code to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as temp_file:
                temp_file.write(code)
                temp_file_path = temp_file.name
            
            try:
                # Run the reverse engineer tool beautify command
                result = subprocess.run(
                    ["node", "cli.js", "beautify", temp_file_path],
                    cwd=tool_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    beautified_code = result.stdout
                    return True, beautified_code
                else:
                    logger.error(f"Beautification failed: {result.stderr}")
                    return False, f"Beautification failed: {result.stderr}"
                    
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_file_path)
                except OSError:
                    pass
                    
        except subprocess.TimeoutExpired:
            logger.error("Code beautification timed out")
            return False, "Beautification timed out"
        except Exception as e:
            logger.error(f"Code beautification failed: {str(e)}")
            return False, f"Beautification failed: {str(e)}"
    
    def extract_functions(self, code: str) -> List[Dict[str, Any]]:
        """Extract function information from JavaScript code."""
        functions = []
        
        try:
            # Simple regex-based function extraction (basic implementation)
            function_patterns = [
                r'function\s+(\w+)\s*\([^)]*\)\s*{',
                r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*{',
                r'var\s+(\w+)\s*=\s*function\s*\([^)]*\)\s*{',
                r'let\s+(\w+)\s*=\s*function\s*\([^)]*\)\s*{'
            ]
            
            for pattern in function_patterns:
                matches = re.finditer(pattern, code, re.MULTILINE)
                for match in matches:
                    func_name = match.group(1)
                    start_pos = match.start()
                    
                    # Find line number
                    lines_before = code[:start_pos].count('\n')
                    column = start_pos - code.rfind('\n', 0, start_pos) - 1
                    
                    functions.append({
                        "name": func_name,
                        "parameters": [],  # Would need more sophisticated parsing
                        "complexity": 1,   # Would need AST analysis for accurate complexity
                        "location": {
                            "start": {
                                "line": lines_before + 1,
                                "column": column
                            }
                        }
                    })
            
            logger.info(f"Extracted {len(functions)} functions")
            
        except Exception as e:
            logger.error(f"Function extraction failed: {str(e)}")
        
        return functions
    
    def extract_variables(self, code: str) -> List[str]:
        """Extract variable names from JavaScript code."""
        variables = set()
        
        try:
            # Extract variable declarations
            var_patterns = [
                r'var\s+(\w+)',
                r'let\s+(\w+)',
                r'const\s+(\w+)',
                r'function\s+(\w+)\s*\(',
                r'(\w+)\s*=\s*function',
                r'(\w+)\s*=\s*\('
            ]
            
            for pattern in var_patterns:
                matches = re.findall(pattern, code)
                variables.update(matches)
            
            # Filter out common JavaScript keywords
            js_keywords = {
                'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
                'break', 'continue', 'return', 'try', 'catch', 'finally', 'throw',
                'new', 'typeof', 'instanceof', 'in', 'delete', 'void', 'this',
                'function', 'var', 'let', 'const', 'class', 'extends', 'import',
                'export', 'from', 'as', 'default', 'async', 'await', 'yield'
            }
            
            variables = [var for var in variables if var not in js_keywords]
            logger.info(f"Extracted {len(variables)} variables")
            
        except Exception as e:
            logger.error(f"Variable extraction failed: {str(e)}")
        
        return sorted(list(variables))
    
    def extract_strings(self, code: str) -> List[str]:
        """Extract string literals from JavaScript code."""
        strings = []
        
        try:
            # Extract single and double quoted strings
            string_patterns = [
                r"'([^'\\]*(\\.[^'\\]*)*)'",
                r'"([^"\\]*(\\.[^"\\]*)*)"',
                r'`([^`\\]*(\\.[^`\\]*)*)`'
            ]
            
            for pattern in string_patterns:
                matches = re.findall(pattern, code)
                strings.extend(matches)
            
            # Remove duplicates and filter out very short strings
            strings = list(set([s for s in strings if len(s.strip()) > 2]))
            logger.info(f"Extracted {len(strings)} strings")
            
        except Exception as e:
            logger.error(f"String extraction failed: {str(e)}")
        
        return sorted(strings)
    
    def detect_patterns(self, code: str) -> List[Dict[str, Any]]:
        """Detect common obfuscation patterns in JavaScript code."""
        patterns = []
        
        try:
            # Check for eval usage
            eval_matches = list(re.finditer(r'eval\s*\(', code))
            for match in eval_matches:
                line_num = code[:match.start()].count('\n') + 1
                patterns.append({
                    "type": "Dynamic Code Execution",
                    "description": "Usage of eval() detected",
                    "location": {
                        "start": {
                            "line": line_num,
                            "column": match.start() - code.rfind('\n', 0, match.start()) - 1
                        }
                    }
                })
            
            # Check for Function constructor
            func_matches = list(re.finditer(r'Function\s*\(', code))
            for match in func_matches:
                line_num = code[:match.start()].count('\n') + 1
                patterns.append({
                    "type": "Dynamic Code Execution",
                    "description": "Usage of Function() constructor detected",
                    "location": {
                        "start": {
                            "line": line_num,
                            "column": match.start() - code.rfind('\n', 0, match.start()) - 1
                        }
                    }
                })
            
            # Check for hex-encoded strings
            hex_matches = list(re.finditer(r'\\x[0-9a-fA-F]{2}', code))
            if hex_matches:
                patterns.append({
                    "type": "Hex-Encoded Strings",
                    "description": f"Found {len(hex_matches)} hex-encoded string patterns",
                    "location": {
                        "start": {
                            "line": 1,
                            "column": 0
                        }
                    }
                })
            
            # Check for base64 patterns
            b64_matches = list(re.finditer(r'[A-Za-z0-9+/]{20,}={0,2}', code))
            if b64_matches:
                patterns.append({
                    "type": "Base64 Encoding",
                    "description": f"Found {len(b64_matches)} potential base64-encoded strings",
                    "location": {
                        "start": {
                            "line": 1,
                            "column": 0
                        }
                    }
                })
            
            # Check for string concatenation obfuscation
            concat_matches = list(re.finditer(r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']', code))
            if len(concat_matches) > 5:
                patterns.append({
                    "type": "String Concatenation Obfuscation",
                    "description": f"Found {len(concat_matches)} string concatenation patterns",
                    "location": {
                        "start": {
                            "line": 1,
                            "column": 0
                        }
                    }
                })
            
            # Check for array index obfuscation
            array_matches = list(re.finditer(r'\w+\[\d+\]', code))
            if len(array_matches) > 10:
                patterns.append({
                    "type": "Array Index Obfuscation",
                    "description": f"Found {len(array_matches)} array index access patterns",
                    "location": {
                        "start": {
                            "line": 1,
                            "column": 0
                        }
                    }
                })
            
            logger.info(f"Detected {len(patterns)} obfuscation patterns")
            
        except Exception as e:
            logger.error(f"Pattern detection failed: {str(e)}")
        
        return patterns
    
    def analyze_control_flow(self, code: str) -> Dict[str, Any]:
        """Analyze control flow and calculate complexity metrics."""
        control_flow = {
            "structures": [],
            "complexity": 1,  # Base complexity
            "max_nesting": 0
        }
        
        try:
            # Count control flow structures
            if_patterns = len(re.findall(r'\bif\s*\(', code))
            else_patterns = len(re.findall(r'\belse\b', code))
            for_patterns = len(re.findall(r'\bfor\s*\(', code))
            while_patterns = len(re.findall(r'\bwhile\s*\(', code))
            switch_patterns = len(re.findall(r'\bswitch\s*\(', code))
            try_patterns = len(re.findall(r'\btry\s*{', code))
            catch_patterns = len(re.findall(r'\bcatch\s*\(', code))
            
            # Calculate cyclomatic complexity
            control_flow["complexity"] = 1 + if_patterns + for_patterns + while_patterns + switch_patterns + catch_patterns
            
            # Simple nesting detection (basic implementation)
            lines = code.split('\n')
            current_nesting = 0
            max_nesting = 0
            
            for line in lines:
                stripped = line.strip()
                if any(stripped.startswith(keyword) for keyword in ['if', 'for', 'while', 'switch', 'try', 'function']):
                    current_nesting += 1
                    max_nesting = max(max_nesting, current_nesting)
                elif stripped in ['}', '});']:
                    current_nesting = max(0, current_nesting - 1)
            
            control_flow["max_nesting"] = max_nesting
            
            # Store structure information
            control_flow["structures"] = [
                {"type": "if", "count": if_patterns},
                {"type": "for", "count": for_patterns},
                {"type": "while", "count": while_patterns},
                {"type": "switch", "count": switch_patterns},
                {"type": "try", "count": try_patterns},
                {"type": "catch", "count": catch_patterns}
            ]
            
            logger.info(f"Control flow analysis completed - Complexity: {control_flow['complexity']}, Max nesting: {control_flow['max_nesting']}")
            
        except Exception as e:
            logger.error(f"Control flow analysis failed: {str(e)}")
        
        return control_flow
    
    def generate_recommendations(self, control_flow: Dict[str, Any], functions: List[Dict]) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        try:
            complexity = control_flow.get("complexity", 0)
            max_nesting = control_flow.get("max_nesting", 0)
            
            # Complexity recommendations
            if complexity > 20:
                recommendations.append("Overall: ⚠ Very high cyclomatic complexity - consider major refactoring.")
            elif complexity > 10:
                recommendations.append("Overall: ⚠ High cyclomatic complexity - code may be difficult to test and maintain.")
            elif complexity > 5:
                recommendations.append("Overall: • Moderate complexity - acceptable but monitor growth.")
            else:
                recommendations.append("Overall: ✓ Low complexity - code is easy to understand and maintain.")
            
            # Nesting recommendations
            if max_nesting > 4:
                recommendations.append("Overall: ⚠ Deep nesting detected - consider flattening logic or extracting functions.")
            
            # Function-specific recommendations
            for func in functions:
                func_complexity = func.get("complexity", 1)
                if func_complexity > 10:
                    recommendations.append(f"Function '{func['name']}: Very high complexity - consider splitting into smaller functions.")
                elif func_complexity > 5:
                    recommendations.append(f"Function '{func['name']}: High complexity - consider refactoring.")
            
            logger.info(f"Generated {len(recommendations)} recommendations")
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {str(e)}")
        
        return recommendations
    
    def analyze_javascript(self, config: Dict) -> Dict:
        """
        Complete JavaScript analysis process.
        
        Args:
            config: Configuration dictionary with analysis parameters and code
            
        Returns:
            Dictionary with analysis results
        """
        result = {
            "success": False,
            "message": "",
            "statistics": {},
            "functions": [],
            "variables": [],
            "strings": [],
            "patterns": [],
            "control_flow": {},
            "recommendations": [],
            "beautified_code": None,
            "error": None,
            "timestamp": datetime.now().isoformat()
        }
        
        # Validate configuration
        is_valid, validation_message = self.validate_config(config)
        if not is_valid:
            result["error"] = validation_message
            result["message"] = "Configuration validation failed"
            return result
        
        code = config["code"]
        analysis_config = config.get("analysis_config", self.analysis_config)
        
        try:
            # Step 1: Basic statistics
            lines = len(code.split('\n'))
            result["statistics"]["lines"] = lines
            
            # Step 2: Extract functions
            if analysis_config.get("extract_functions", True):
                result["functions"] = self.extract_functions(code)
                result["statistics"]["functions"] = len(result["functions"])
            
            # Step 3: Extract variables
            if analysis_config.get("extract_variables", True):
                result["variables"] = self.extract_variables(code)
                result["statistics"]["variables"] = len(result["variables"])
            
            # Step 4: Extract strings
            if analysis_config.get("extract_strings", True):
                result["strings"] = self.extract_strings(code)
                result["statistics"]["strings"] = len(result["strings"])
            
            # Step 5: Detect patterns
            if analysis_config.get("detect_patterns", True):
                result["patterns"] = self.detect_patterns(code)
                result["statistics"]["patterns"] = len(result["patterns"])
            
            # Step 6: Analyze control flow
            if analysis_config.get("analyze_control_flow", True):
                result["control_flow"] = self.analyze_control_flow(code)
                result["statistics"]["complexity"] = result["control_flow"]["complexity"]
            
            # Step 7: Generate recommendations
            if analysis_config.get("generate_report", True):
                result["recommendations"] = self.generate_recommendations(
                    result["control_flow"], 
                    result["functions"]
                )
            
            # Step 8: Beautify code
            if analysis_config.get("beautify_code", True):
                success, beautified_code = self.beautify_code(code)
                if success:
                    result["beautified_code"] = beautified_code
            
            # Success
            result["success"] = True
            result["message"] = "JavaScript analysis completed successfully"
            logger.info("JavaScript analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            result["error"] = str(e)
            result["message"] = "Analysis failed"
        
        return result
    
    def generate_analysis_report(self, analysis_result: Dict, original_code: str) -> str:
        """Generate a comprehensive analysis report."""
        try:
            report = []
            report.append("JAVASCRIPT REVERSE ENGINEER ANALYSIS REPORT")
            report.append("=" * 50)
            report.append(f"Generated: {analysis_result.get('timestamp', 'Unknown')}")
            report.append("")
            
            # Statistics
            stats = analysis_result.get("statistics", {})
            report.append("CODE STATISTICS")
            report.append("-" * 20)
            report.append(f"Lines of code: {stats.get('lines', 0)}")
            report.append(f"Functions: {stats.get('functions', 0)}")
            report.append(f"Variables: {stats.get('variables', 0)}")
            report.append(f"Strings: {stats.get('strings', 0)}")
            report.append(f"Cyclomatic complexity: {stats.get('complexity', 0)}")
            report.append(f"Patterns detected: {stats.get('patterns', 0)}")
            report.append("")
            
            # Functions
            functions = analysis_result.get("functions", [])
            if functions:
                report.append("FUNCTIONS FOUND")
                report.append("-" * 20)
                for func in functions:
                    location = func.get("location", {}).get("start", {})
                    report.append(f"- {func.get('name', 'unknown')}() - Line {location.get('line', '?')}, Complexity: {func.get('complexity', '?')}")
                report.append("")
            
            # Patterns
            patterns = analysis_result.get("patterns", [])
            if patterns:
                report.append("PATTERNS DETECTED")
                report.append("-" * 20)
                for pattern in patterns:
                    report.append(f"- {pattern.get('type', 'Unknown')}: {pattern.get('description', 'No description')}")
                report.append("")
            
            # Recommendations
            recommendations = analysis_result.get("recommendations", [])
            if recommendations:
                report.append("RECOMMENDATIONS")
                report.append("-" * 20)
                for rec in recommendations:
                    report.append(f"- {rec}")
                report.append("")
            
            # Beautified code (truncated)
            if analysis_result.get("beautified_code"):
                report.append("BEAUTIFIED CODE")
                report.append("-" * 20)
                beautified = analysis_result["beautified_code"]
                # Show first 500 characters
                if len(beautified) > 500:
                    report.append(beautified[:500] + "\n... (truncated)")
                else:
                    report.append(beautified)
                report.append("")
            
            report.append("END OF REPORT")
            
            return "\n".join(report)
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            return f"Error generating report: {str(e)}"

# Module initialization
def create_reverse_engineer_module():
    """Create and return a Reverse Engineer module instance."""
    return JavaScriptReverseEngineer()

# Export the main class
__all__ = ['JavaScriptReverseEngineer', 'create_reverse_engineer_module']
