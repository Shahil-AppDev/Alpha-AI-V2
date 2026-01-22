"""
RustDesk Module
===============

This module provides functionality for managing RustDesk remote desktop operations
including deployment, configuration, and server management.
"""

import os
import subprocess
import requests
import json
import logging
import shutil
from typing import Dict, Optional, Tuple, List
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class RustDeskManager:
    """
    RustDesk remote desktop management class for security testing purposes.
    
    WARNING: This tool should only be used for authorized penetration testing
    and security assessment. Unauthorized use is illegal and unethical.
    """
    
    def __init__(self):
        self.supported_platforms = ["windows", "linux", "macos"]
        self.build_types = ["source", "binary"]
        self.default_config = {
            "server_type": "public",
            "custom_server": "",
            "key": "",
            "relay_server": "",
            "port": 21116,
            "auto_start": True,
            "direct_ip": False
        }
        
        # Platform-specific download URLs
        self.download_urls = {
            "windows": "https://github.com/rustdesk/rustdesk/releases/latest/download/rustdesk-x64-sciter.exe",
            "linux": "https://github.com/rustdesk/rustdesk/releases/latest/download/rustdesk-x86_64.AppImage",
            "macos": "https://github.com/rustdesk/rustdesk/releases/latest/download/rustdesk-x64.dmg"
        }
        
    def validate_config(self, config: Dict) -> Tuple[bool, str]:
        """Validate the provided configuration."""
        required_fields = ["server_type", "platform", "build_type"]
        
        for field in required_fields:
            if field not in config:
                return False, f"Missing required field: {field}"
        
        # Validate platform
        if config["platform"] not in self.supported_platforms:
            return False, f"Unsupported platform: {config['platform']}"
        
        # Validate build type
        if config["build_type"] not in self.build_types:
            return False, f"Unsupported build type: {config['build_type']}"
        
        # Validate custom server if specified
        if config["server_type"] == "custom" and not config.get("custom_server"):
            return False, "Custom server URL required when server type is 'custom'"
        
        return True, "Configuration is valid"
    
    def check_dependencies(self, platform: str) -> Tuple[bool, List[str]]:
        """Check if required dependencies are installed."""
        missing_deps = []
        
        try:
            if platform == "windows":
                # Check for Visual Studio Build Tools
                result = subprocess.run(["where", "cl"], capture_output=True, text=True)
                if result.returncode != 0:
                    missing_deps.append("Visual Studio Build Tools")
                
                # Check for vcpkg
                result = subprocess.run(["where", "vcpkg"], capture_output=True, text=True)
                if result.returncode != 0:
                    missing_deps.append("vcpkg")
                    
            elif platform == "linux":
                # Check for common build tools
                tools = ["gcc", "git", "cmake", "make"]
                for tool in tools:
                    result = subprocess.run(["which", tool], capture_output=True, text=True)
                    if result.returncode != 0:
                        missing_deps.append(tool)
                        
                # Check for vcpkg
                result = subprocess.run(["which", "vcpkg"], capture_output=True, text=True)
                if result.returncode != 0:
                    missing_deps.append("vcpkg")
                    
            elif platform == "macos":
                # Check for Xcode tools
                result = subprocess.run(["which", "clang"], capture_output=True, text=True)
                if result.returncode != 0:
                    missing_deps.append("Xcode Command Line Tools")
                
                # Check for Homebrew
                result = subprocess.run(["which", "brew"], capture_output=True, text=True)
                if result.returncode != 0:
                    missing_deps.append("Homebrew")
        
        except Exception as e:
            logger.error(f"Dependency check failed: {str(e)}")
            return False, ["Dependency check failed"]
        
        return len(missing_deps) == 0, missing_deps
    
    def download_rustdesk(self, platform: str, destination: str) -> Tuple[bool, str]:
        """Download RustDesk binary for the specified platform."""
        try:
            logger.info(f"Downloading RustDesk for {platform}")
            
            if platform not in self.download_urls:
                return False, f"Unsupported platform: {platform}"
            
            url = self.download_urls[platform]
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            
            with open(destination, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info(f"RustDesk downloaded to {destination}")
            return True, f"Downloaded to {destination}"
            
        except Exception as e:
            logger.error(f"Failed to download RustDesk: {str(e)}")
            return False, f"Download failed: {str(e)}"
    
    def setup_build_environment(self, platform: str) -> Tuple[bool, str]:
        """Set up the build environment for compiling RustDesk from source."""
        try:
            logger.info(f"Setting up build environment for {platform}")
            
            if platform == "windows":
                # Install vcpkg dependencies
                deps = ["libvpx:x64-windows-static", "libyuv:x64-windows-static", 
                       "opus:x64-windows-static", "aom:x64-windows-static"]
                
                for dep in deps:
                    cmd = ["vcpkg", "install", dep]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                    if result.returncode != 0:
                        return False, f"Failed to install {dep}: {result.stderr}"
                        
            elif platform in ["linux", "macos"]:
                # Install vcpkg dependencies
                deps = ["libvpx", "libyuv", "opus", "aom"]
                
                for dep in deps:
                    cmd = ["vcpkg", "install", dep]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                    if result.returncode != 0:
                        return False, f"Failed to install {dep}: {result.stderr}"
            
            logger.info("Build environment setup completed")
            return True, "Build environment ready"
            
        except subprocess.TimeoutExpired:
            logger.error("Build environment setup timed out")
            return False, "Setup timed out"
        except Exception as e:
            logger.error(f"Build environment setup failed: {str(e)}")
            return False, f"Setup failed: {str(e)}"
    
    def build_rustdesk(self, platform: str, build_dir: str) -> Tuple[bool, str]:
        """Build RustDesk from source."""
        try:
            logger.info(f"Building RustDesk for {platform}")
            
            # Clone the repository
            repo_url = "https://github.com/rustdesk/rustdesk.git"
            if not os.path.exists(build_dir):
                subprocess.run(["git", "clone", "--recurse-submodules", repo_url, build_dir], 
                             check=True, timeout=300)
            
            os.chdir(build_dir)
            
            # Set environment variables
            env = os.environ.copy()
            if "VCPKG_ROOT" in os.environ:
                env["VCPKG_ROOT"] = os.environ["VCPKG_ROOT"]
            
            # Build the project
            build_cmd = ["cargo", "build", "--release"]
            result = subprocess.run(build_cmd, env=env, capture_output=True, text=True, timeout=1800)
            
            if result.returncode == 0:
                logger.info("RustDesk built successfully")
                return True, "Build completed successfully"
            else:
                logger.error(f"Build failed: {result.stderr}")
                return False, f"Build failed: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            logger.error("Build timed out")
            return False, "Build timed out"
        except Exception as e:
            logger.error(f"Build failed: {str(e)}")
            return False, f"Build error: {str(e)}"
    
    def configure_rustdesk(self, config: Dict) -> Tuple[bool, str]:
        """Configure RustDesk with the provided settings."""
        try:
            logger.info("Configuring RustDesk settings")
            
            # Create configuration directory
            config_dir = os.path.expanduser("~/.config/rustdesk")
            os.makedirs(config_dir, exist_ok=True)
            
            # Generate configuration file
            config_data = {
                "server_type": config["server_type"],
                "custom_server": config.get("custom_server", ""),
                "key": config.get("key", ""),
                "relay_server": config.get("relay_server", ""),
                "port": config.get("port", 21116),
                "auto_start": config.get("auto_start", True),
                "direct_ip": config.get("direct_ip", False)
            }
            
            config_file = os.path.join(config_dir, "config.toml")
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info("RustDesk configuration completed")
            return True, "Configuration saved successfully"
            
        except Exception as e:
            logger.error(f"Configuration failed: {str(e)}")
            return False, f"Configuration error: {str(e)}"
    
    def generate_connection_id(self) -> str:
        """Generate a unique connection ID for RustDesk."""
        import random
        import string
        
        # Generate a random 9-character ID
        chars = string.ascii_lowercase + string.digits
        return "rustdesk-" + ''.join(random.choice(chars) for _ in range(9))
    
    def deploy_rustdesk(self, config: Dict) -> Dict:
        """
        Complete RustDesk deployment process.
        
        Args:
            config: Configuration dictionary with deployment parameters
            
        Returns:
            Dictionary with deployment results
        """
        result = {
            "success": False,
            "message": "",
            "connection_id": None,
            "server_url": None,
            "error": None,
            "timestamp": datetime.now().isoformat()
        }
        
        # Validate configuration
        is_valid, validation_message = self.validate_config(config)
        if not is_valid:
            result["error"] = validation_message
            result["message"] = "Configuration validation failed"
            return result
        
        platform = config["platform"]
        build_type = config["build_type"]
        
        try:
            # Step 1: Check dependencies
            deps_ok, missing_deps = self.check_dependencies(platform)
            if not deps_ok:
                result["error"] = f"Missing dependencies: {', '.join(missing_deps)}"
                result["message"] = "Dependency check failed"
                return result
            
            # Step 2: Download or build
            if build_type == "binary":
                # Download binary
                download_path = f"/tmp/rustdesk-{platform}"
                success, message = self.download_rustdesk(platform, download_path)
                if not success:
                    result["error"] = message
                    result["message"] = "Download failed"
                    return result
            else:
                # Build from source
                build_dir = "/tmp/rustdesk-build"
                success, message = self.setup_build_environment(platform)
                if not success:
                    result["error"] = message
                    result["message"] = "Build environment setup failed"
                    return result
                
                success, message = self.build_rustdesk(platform, build_dir)
                if not success:
                    result["error"] = message
                    result["message"] = "Build failed"
                    return result
            
            # Step 3: Configure
            success, message = self.configure_rustdesk(config)
            if not success:
                result["error"] = message
                result["message"] = "Configuration failed"
                return result
            
            # Step 4: Generate connection details
            connection_id = self.generate_connection_id()
            
            # Determine server URL
            if config["server_type"] == "public":
                server_url = "rs-sg.rustdesk.com"
            elif config["server_type"] == "private":
                server_url = "private.rustdesk.com"
            else:
                server_url = config.get("custom_server", "custom.server.com")
            
            # Success
            result["success"] = True
            result["message"] = "RustDesk deployed successfully"
            result["connection_id"] = connection_id
            result["server_url"] = server_url
            
            logger.info("RustDesk deployment completed successfully")
            
        except Exception as e:
            logger.error(f"Deployment failed: {str(e)}")
            result["error"] = str(e)
            result["message"] = "Deployment failed"
        
        return result
    
    def generate_deployment_commands(self, config: Dict) -> str:
        """Generate deployment commands for the specified platform and build type."""
        platform = config["platform"]
        build_type = config["build_type"]
        
        commands = []
        commands.append(f"# RustDesk Deployment Commands")
        commands.append(f"# Platform: {platform}")
        commands.append(f"# Build Type: {build_type}")
        commands.append("")
        
        if build_type == "source":
            if platform == "windows":
                commands.extend([
                    "# Install vcpkg",
                    "git clone https://github.com/microsoft/vcpkg",
                    "cd vcpkg",
                    "git checkout 2023.04.15",
                    "cd ..",
                    "vcpkg/bootstrap-vcpkg.bat",
                    "vcpkg/vcpkg install libvpx:x64-windows-static libyuv:x64-windows-static opus:x64-windows-static aom:x64-windows-static",
                    "",
                    "# Set environment variable",
                    "set VCPKG_ROOT=%CD%\\vcpkg",
                    "",
                    "# Build RustDesk",
                    "git clone --recurse-submodules https://github.com/rustdesk/rustdesk",
                    "cd rustdesk",
                    "cargo run --release"
                ])
            elif platform == "linux":
                commands.extend([
                    "# Install system dependencies",
                    "sudo apt install -y zip g++ gcc git curl wget nasm yasm libgtk-3-dev clang libxcb-randr0-dev libxdo-dev libxfixes-dev libxcb-shape0-dev libxcb-xfixes0-dev libasound2-dev libpulse-dev cmake make libclang-dev ninja-build libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libpam0g-dev",
                    "",
                    "# Install vcpkg",
                    "git clone https://github.com/microsoft/vcpkg",
                    "cd vcpkg",
                    "git checkout 2023.04.15",
                    "cd ..",
                    "vcpkg/bootstrap-vcpkg.sh",
                    "export VCPKG_ROOT=$HOME/vcpkg",
                    "vcpkg/vcpkg install libvpx libyuv opus aom",
                    "",
                    "# Build RustDesk",
                    "git clone --recurse-submodules https://github.com/rustdesk/rustdesk",
                    "cd rustdesk",
                    "cargo run --release"
                ])
            else:  # macOS
                commands.extend([
                    "# Install dependencies with Homebrew",
                    "brew install rust git nasm yasm cmake",
                    "",
                    "# Install vcpkg",
                    "git clone https://github.com/microsoft/vcpkg",
                    "cd vcpkg",
                    "git checkout 2023.04.15",
                    "cd ..",
                    "vcpkg/bootstrap-vcpkg.sh",
                    "export VCPKG_ROOT=$HOME/vcpkg",
                    "vcpkg/vcpkg install libvpx libyuv opus aom",
                    "",
                    "# Build RustDesk",
                    "git clone --recurse-submodules https://github.com/rustdesk/rustdesk",
                    "cd rustdesk",
                    "cargo run --release"
                ])
        else:  # binary deployment
            commands.extend([
                "# Download latest release",
                f"wget {self.download_urls[platform]}",
                "",
                "# Install/configure"
            ])
            
            if platform == "windows":
                commands.extend([
                    "# Run installer",
                    "rustdesk-x64-sciter.exe /S"
                ])
            elif platform == "linux":
                commands.extend([
                    "# Make executable and run",
                    "chmod +x rustdesk-x86_64.AppImage",
                    "./rustdesk-x86_64.AppImage"
                ])
            else:  # macOS
                commands.extend([
                    "# Mount DMG and install",
                    "hdiutil attach rustdesk-x64.dmg",
                    "sudo cp -R /Volumes/RustDesk/RustDesk.app /Applications/",
                    "hdiutil detach /Volumes/RustDesk"
                ])
        
        # Add configuration commands
        commands.extend([
            "",
            "# Configure server settings",
            f"rustdesk --key {config.get('key', '')} --relay-server {config.get('relay_server', '')}"
        ])
        
        return "\n".join(commands)
    
    def get_server_status(self, server_url: str) -> Tuple[bool, str]:
        """Check the status of a RustDesk server."""
        try:
            # Simple connectivity check
            import socket
            host, port = server_url.split(":") if ":" in server_url else (server_url, 21116)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, int(port)))
            sock.close()
            
            if result == 0:
                return True, "Server is accessible"
            else:
                return False, "Server is not accessible"
                
        except Exception as e:
            logger.error(f"Server status check failed: {str(e)}")
            return False, f"Status check failed: {str(e)}"

# Module initialization
def create_rustdesk_module():
    """Create and return a RustDesk module instance."""
    return RustDeskManager()

# Export the main class
__all__ = ['RustDeskManager', 'create_rustdesk_module']
