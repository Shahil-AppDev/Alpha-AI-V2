#!/usr/bin/env python3
"""
Reverse Engineering Module - Binary analysis and disassembly capabilities.
This module provides tools for analyzing binary snippets and assembly code using angr and LLM.
"""

import os
import re
import json
import logging
import tempfile
import binascii
from typing import Dict, Any, Optional, List, Union
from pathlib import Path

# Import reverse engineering libraries
try:
    import angr
    import archinfo
    import cle
    from angr import Project
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    logging.warning("angr not available - some features will be limited")

# Import capstone for disassembly
try:
    import capstone
    from capstone import *
    from capstone.x86 import *
    from capstone.arm import *
    from capstone.arm64 import *
    from capstone.mips import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logging.warning("capstone not available - using fallback disassembly")

# Import LLM client for analysis
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReverseEngineeringAnalyzer:
    """
    Binary analysis and reverse engineering with angr and LLM integration.
    """
    
    def __init__(self, llm_endpoint: str = None, llm_api_key: str = None):
        """
        Initialize the reverse engineering analyzer.
        
        Args:
            llm_endpoint: LLM API endpoint for code analysis
            llm_api_key: API key for LLM service
        """
        self.llm_endpoint = llm_endpoint or os.getenv("LLM_ENDPOINT", "http://llm-service:8000/generate")
        self.llm_api_key = llm_api_key or os.getenv("LLM_API_KEY", "test-key")
        
        # Supported architectures
        self.supported_architectures = {}
        if CAPSTONE_AVAILABLE:
            try:
                self.supported_architectures["x86"] = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                self.supported_architectures["x86_64"] = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                self.supported_architectures["arm"] = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
                self.supported_architectures["arm64"] = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                self.supported_architectures["mips"] = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_32)
            except Exception as e:
                logging.warning(f"Failed to initialize capstone architectures: {e}")
                self.capstone_available = False
        else:
            self.capstone_available = False
        
        # Architecture mapping for angr
        self.angr_architectures = {
            "x86": archinfo.ArchX86(),
            "x86_64": archinfo.ArchAMD64(),
            "arm": archinfo.ArchARM(),
            "arm64": archinfo.ArchAArch64(),
            "mips": archinfo.ArchMIPS32(),
        }
        
        logger.info(f"ReverseEngineeringAnalyzer initialized - angr: {ANGR_AVAILABLE}, capstone: {CAPSTONE_AVAILABLE}")
    
    def _call_llm(self, prompt: str) -> str:
        """
        Make a call to the LLM for code analysis.
        
        Args:
            prompt: The prompt to send to the LLM
            
        Returns:
            Analysis from the LLM
        """
        try:
            payload = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {
                        "role": "system", 
                        "content": "You are an expert reverse engineer and security analyst. Analyze the provided assembly code or binary analysis results to identify functionality, potential vulnerabilities, and security implications. Provide detailed technical analysis."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": 1500,
                "temperature": 0.3
            }
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.llm_api_key}"
            }
            
            response = requests.post(
                self.llm_endpoint,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            response.raise_for_status()
            result = response.json()
            
            return result.get("choices", [{}])[0].get("message", {}).get("content", "")
            
        except Exception as e:
            logger.error(f"Error calling LLM: {e}")
            raise Exception(f"Failed to get LLM analysis: {str(e)}")
    
    def analyze_binary_snippet(self, binary_data: bytes, architecture: str = "x86_64") -> Dict[str, Any]:
        """
        Analyze binary snippet using angr and LLM for vulnerability identification.
        
        Args:
            binary_data: Raw binary bytes to analyze
            architecture: Target architecture (x86, x86_64, arm, arm64, mips)
            
        Returns:
            Dictionary containing analysis results and metadata
        """
        try:
            # Validate inputs
            if not binary_data:
                return {
                    "success": False,
                    "error": "No binary data provided"
                }
            
            if architecture not in self.supported_architectures:
                return {
                    "success": False,
                    "error": f"Unsupported architecture: {architecture}. Supported: {', '.join(self.supported_architectures.keys())}"
                }
            
            logger.info(f"Analyzing binary snippet ({len(binary_data)} bytes) for {architecture}")
            
            # Perform static analysis
            analysis_results = {}
            
            # 1. Basic binary information
            analysis_results["binary_info"] = self._analyze_binary_info(binary_data)
            
            # 2. String extraction
            analysis_results["strings"] = self._extract_strings(binary_data)
            
            # 3. Disassembly using capstone
            analysis_results["disassembly"] = self._disassemble_binary(binary_data, architecture)
            
            # 4. Basic pattern analysis
            analysis_results["patterns"] = self._analyze_patterns(binary_data)
            
            # 5. Advanced analysis with angr if available
            if ANGR_AVAILABLE and len(binary_data) > 16:  # Minimum size for meaningful analysis
                try:
                    analysis_results["angr_analysis"] = self._analyze_with_angr(binary_data, architecture)
                except Exception as e:
                    logger.warning(f"angr analysis failed: {e}")
                    analysis_results["angr_analysis"] = {"error": str(e)}
            
            # 6. LLM analysis for vulnerability identification
            analysis_results["llm_analysis"] = self._get_llm_analysis(analysis_results, architecture)
            
            # 7. Security assessment
            analysis_results["security_assessment"] = self._assess_security(analysis_results)
            
            return {
                "success": True,
                "architecture": architecture,
                "binary_size": len(binary_data),
                "analysis": analysis_results,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing binary snippet: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _analyze_binary_info(self, binary_data: bytes) -> Dict[str, Any]:
        """Analyze basic binary information."""
        info = {}
        
        # File magic bytes
        info["magic_bytes"] = binary_data[:8].hex()
        
        # Entropy calculation (basic)
        entropy = self._calculate_entropy(binary_data)
        info["entropy"] = round(entropy, 2)
        info["is_encrypted"] = entropy > 7.0  # High entropy suggests encryption/compression
        
        # Check for common file signatures
        signatures = {
            b"\x7fELF": "ELF executable",
            b"MZ": "PE executable (Windows)",
            b"\xca\xfe\xba\xbe": "Java class file",
            b"\xfe\xed\xfa\xce": "Mach-O executable (macOS)",
            b"\xfe\xed\xfa\xcf": "Mach-O executable (macOS, 64-bit)",
        }
        
        for sig, desc in signatures.items():
            if binary_data.startswith(sig):
                info["file_type"] = desc
                break
        else:
            info["file_type"] = "Unknown raw binary"
        
        return info
    
    def _extract_strings(self, binary_data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data."""
        strings = []
        current_string = ""
        
        for byte in binary_data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # Add final string if valid
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        # Filter for interesting strings
        interesting_strings = []
        keywords = ["http", "ftp", "password", "admin", "root", "user", "login", "key", "secret", "token"]
        
        for s in strings:
            if any(keyword.lower() in s.lower() for keyword in keywords) or len(s) > 10:
                interesting_strings.append(s)
        
        return interesting_strings[:50]  # Limit to prevent excessive output
    
    def _disassemble_binary(self, binary_data: bytes, architecture: str) -> Dict[str, Any]:
        """Disassemble binary using capstone."""
        if not CAPSTONE_AVAILABLE:
            return {"error": "Capstone not available for disassembly"}
        
        cs = self.supported_architectures[architecture]
        if not cs:
            return {"error": f"Architecture {architecture} not supported by capstone"}
        
        try:
            instructions = []
            disasm = cs.disasm(binary_data, 0x1000)  # Start at offset 0x1000
            
            for i, insn in enumerate(disasm):
                if i >= 100:  # Limit to prevent excessive output
                    break
                instructions.append({
                    "address": hex(insn.address),
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "size": insn.size,
                    "bytes": insn.bytes.hex()
                })
            
            # Analyze instruction patterns
            patterns = self._analyze_instruction_patterns(instructions)
            
            return {
                "instructions": instructions,
                "instruction_count": len(instructions),
                "patterns": patterns
            }
            
        except Exception as e:
            return {"error": f"Disassembly failed: {str(e)}"}
    
    def _analyze_instruction_patterns(self, instructions: List[Dict]) -> Dict[str, Any]:
        """Analyze instruction patterns for security insights."""
        patterns = {
            "function_calls": [],
            "memory_operations": [],
            "control_flow": [],
            "suspicious_instructions": []
        }
        
        for insn in instructions:
            mnemonic = insn["mnemonic"].lower()
            
            # Function calls
            if mnemonic in ["call", "jmp", "ret"]:
                patterns["function_calls"].append(insn)
            
            # Memory operations
            if any(op in mnemonic for op in ["mov", "lea", "push", "pop", "add", "sub"]):
                if "ptr" in insn["op_str"] or "[" in insn["op_str"] or "]" in insn["op_str"]:
                    patterns["memory_operations"].append(insn)
            
            # Control flow
            if mnemonic in ["jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl"]:
                patterns["control_flow"].append(insn)
            
            # Potentially suspicious instructions
            if mnemonic in ["int", "syscall", "cli", "sti", "hlt"]:
                patterns["suspicious_instructions"].append(insn)
        
        # Summarize patterns
        for key in patterns:
            patterns[key + "_count"] = len(patterns[key])
        
        return patterns
    
    def _analyze_patterns(self, binary_data: bytes) -> Dict[str, Any]:
        """Analyze binary patterns for common vulnerabilities."""
        patterns = {
            "shellcode_patterns": [],
            "encryption_constants": [],
            "network_patterns": [],
            "buffer_overflow_risks": []
        }
        
        # Check for common shellcode patterns
        shellcode_signatures = [
            b"\x31\xc0",  # xor eax, eax
            b"\x31\xdb",  # xor ebx, ebx
            b"\x31\xd2",  # xor edx, edx
            b"\x31\xff",  # xor edi, edi
            b"\x6a\x0b",  # push 0xb (sys_execve)
            b"\x58",      # pop eax
            b"\x99",      # cdq
            b"\x52",      # push edx
            b"\x68\x2f\x2f\x73\x68",  # push "//sh"
            b"\x68\x2f\x62\x69\x6e",  # push "/bin"
            b"\x89\xe3",  # mov ebx, esp
            b"\x52",      # push edx
            b"\x53",      # push ebx
            b"\x89\xe1",  # mov ecx, esp
            b"\xcd\x80",  # int 0x80
        ]
        
        for sig in shellcode_signatures:
            if sig in binary_data:
                patterns["shellcode_patterns"].append(sig.hex())
        
        # Check for network-related patterns
        network_patterns = [
            b"127.0.0.1",
            b"192.168.",
            b"10.0.0.",
            b"http://",
            b"ftp://",
            b"tcp",
            b"udp"
        ]
        
        for pattern in network_patterns:
            if pattern in binary_data:
                patterns["network_patterns"].append(pattern.decode('ascii', errors='ignore'))
        
        # Check for potential buffer overflow risks
        if binary_data.count(b"\x90") > 10:  # Many NOPs
            patterns["buffer_overflow_risks"].append("Multiple NOP sleds detected")
        
        return patterns
    
    def _analyze_with_angr(self, binary_data: bytes, architecture: str) -> Dict[str, Any]:
        """Perform advanced analysis using angr."""
        try:
            # Create temporary file for angr
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(binary_data)
                tmp_file_path = tmp_file.name
            
            try:
                # Load binary with angr
                proj = angr.Project(tmp_file_path, load_options={'auto_load_libs': False})
                
                analysis = {
                    "entry_point": hex(proj.entry),
                    "functions": [],
                    "basic_blocks": 0,
                    "cfg_nodes": 0
                }
                
                # Get function information
                if hasattr(proj, 'analyses'):
                    try:
                        cfg = proj.analyses.CFGFast()
                        analysis["basic_blocks"] = len(cfg.graph.nodes())
                        analysis["cfg_nodes"] = len(cfg.graph.nodes())
                        
                        # Get function list
                        functions = list(cfg.functions.values())
                        for func in functions[:20]:  # Limit to prevent excessive output
                            analysis["functions"].append({
                                "name": func.name,
                                "address": hex(func.addr),
                                "size": func.size,
                                "block_count": len(func.blocks)
                            })
                        
                        analysis["function_count"] = len(functions)
                        
                    except Exception as e:
                        analysis["cfg_error"] = str(e)
                
                return analysis
                
            finally:
                # Clean up temporary file
                os.unlink(tmp_file_path)
                
        except Exception as e:
            return {"error": f"angr analysis failed: {str(e)}"}
    
    def _get_llm_analysis(self, analysis_results: Dict[str, Any], architecture: str) -> str:
        """Get LLM analysis of the binary."""
        try:
            # Prepare analysis summary for LLM
            disassembly_info = ""
            if "disassembly" in analysis_results and "instructions" in analysis_results["disassembly"]:
                instructions = analysis_results["disassembly"]["instructions"][:10]  # First 10 instructions
                disassembly_info = "\n".join([
                    f"0x{insn['address']}: {insn['mnemonic']} {insn['op_str']}"
                    for insn in instructions
                ])
            
            strings_info = ""
            if "strings" in analysis_results:
                strings_info = "\n".join(analysis_results["strings"][:10])  # First 10 strings
            
            patterns_info = ""
            if "patterns" in analysis_results:
                patterns = analysis_results["patterns"]
                patterns_info = f"Shellcode patterns: {len(patterns.get('shellcode_patterns', []))}\n"
                patterns_info += f"Network patterns: {len(patterns.get('network_patterns', []))}\n"
                patterns_info += f"Buffer overflow risks: {len(patterns.get('buffer_overflow_risks', []))}"
            
            prompt = f"""
Analyze the following binary analysis results for security vulnerabilities and functionality:

Architecture: {architecture}
Binary Size: {analysis_results.get('binary_info', {}).get('file_type', 'Unknown')}
Entropy: {analysis_results.get('binary_info', {}).get('entropy', 'Unknown')}

Disassembly (first 10 instructions):
{disassembly_info}

Extracted Strings (first 10):
{strings_info}

Pattern Analysis:
{patterns_info}

Please provide:
1. Overall functionality assessment
2. Potential security vulnerabilities
3. Suspicious patterns or behaviors
4. Recommendations for further analysis
5. Risk assessment (Low/Medium/High)

Focus on identifying potential exploits, malware indicators, or security weaknesses.
"""
            
            logger.info("Requesting LLM analysis of binary")
            return self._call_llm(prompt)
            
        except Exception as e:
            logger.error(f"Error getting LLM analysis: {e}")
            return f"LLM analysis failed: {str(e)}"
    
    def _assess_security(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess security risks based on analysis results."""
        assessment = {
            "risk_level": "Low",
            "risk_factors": [],
            "recommendations": []
        }
        
        # Check entropy
        entropy = analysis_results.get("binary_info", {}).get("entropy", 0)
        if entropy > 7.0:
            assessment["risk_factors"].append("High entropy suggests encryption or obfuscation")
            assessment["risk_level"] = "Medium"
        
        # Check for shellcode patterns
        shellcode_count = len(analysis_results.get("patterns", {}).get("shellcode_patterns", []))
        if shellcode_count > 0:
            assessment["risk_factors"].append(f"Shellcode patterns detected ({shellcode_count})")
            assessment["risk_level"] = "High"
        
        # Check for suspicious strings
        strings = analysis_results.get("strings", [])
        suspicious_keywords = ["password", "admin", "root", "key", "secret", "exploit", "shell"]
        for string in strings:
            if any(keyword in string.lower() for keyword in suspicious_keywords):
                assessment["risk_factors"].append(f"Suspicious string found: {string}")
                assessment["risk_level"] = "Medium"
                break
        
        # Check instruction patterns
        if "disassembly" in analysis_results:
            patterns = analysis_results["disassembly"].get("patterns", {})
            if patterns.get("suspicious_instructions_count", 0) > 0:
                assessment["risk_factors"].append("Suspicious system instructions detected")
                assessment["risk_level"] = "Medium"
        
        # Generate recommendations
        if assessment["risk_level"] == "High":
            assessment["recommendations"].extend([
                "Perform detailed dynamic analysis",
                "Check for malware signatures",
                "Isolate and analyze in sandbox environment"
            ])
        elif assessment["risk_level"] == "Medium":
            assessment["recommendations"].extend([
                "Conduct further static analysis",
                "Verify binary source and integrity",
                "Monitor runtime behavior"
            ])
        else:
            assessment["recommendations"].extend([
                "Standard security review recommended",
                "Document analysis findings"
            ])
        
        return assessment
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        import math
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                freq = count / data_len
                entropy -= freq * math.log2(freq)
        
        return entropy
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for metadata."""
        from datetime import datetime
        return datetime.now().isoformat()


# Global reverse engineering analyzer instance
_re_analyzer = None


def get_reverse_engineering_analyzer() -> ReverseEngineeringAnalyzer:
    """Get or create the global reverse engineering analyzer instance."""
    global _re_analyzer
    if _re_analyzer is None:
        _re_analyzer = ReverseEngineeringAnalyzer()
    return _re_analyzer


def analyze_binary_snippet(binary_data: bytes, architecture: str = "x86_64") -> Dict[str, Any]:
    """
    Analyze binary snippet using angr and LLM for vulnerability identification.
    
    Args:
        binary_data: Raw binary bytes to analyze
        architecture: Target architecture (x86, x86_64, arm, arm64, mips)
        
    Returns:
        Dictionary containing analysis results and metadata
    """
    analyzer = get_reverse_engineering_analyzer()
    return analyzer.analyze_binary_snippet(binary_data, architecture)


# Standalone test code
if __name__ == "__main__":
    print("=== Reverse Engineering Module Test ===")
    
    # Test with a simple x86 shellcode example
    test_shellcode = bytes.fromhex("31c048bbd19d9691d0c8b7b248b7b1c8b7b088b7b148b7b1029c989c8b0f05")
    
    print(f"\n1. Testing binary analysis with shellcode ({len(test_shellcode)} bytes):")
    result = analyze_binary_snippet(test_shellcode, "x86_64")
    print(f"Success: {result['success']}")
    
    if result['success']:
        print(f"Architecture: {result['architecture']}")
        print(f"Binary size: {result['binary_size']} bytes")
        
        analysis = result['analysis']
        print(f"File type: {analysis['binary_info']['file_type']}")
        print(f"Entropy: {analysis['binary_info']['entropy']}")
        print(f"Strings found: {len(analysis['strings'])}")
        print(f"Risk level: {analysis['security_assessment']['risk_level']}")
        
        if 'disassembly' in analysis and 'instructions' in analysis['disassembly']:
            print(f"Instructions disassembled: {analysis['disassembly']['instruction_count']}")
        
        print("\nLLM Analysis Summary:")
        llm_analysis = analysis.get('llm_analysis', 'No LLM analysis available')
        print(llm_analysis[:300] + "..." if len(llm_analysis) > 300 else llm_analysis)
    else:
        print(f"Error: {result['error']}")
    
    # Test with different architectures
    print("\n2. Testing architecture validation:")
    result = analyze_binary_snippet(test_shellcode, "invalid_arch")
    print(f"Invalid architecture test: {not result['success']} (Expected)")
    
    print("\n=== Reverse Engineering Module Test Complete ===")
