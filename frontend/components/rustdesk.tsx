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
    Globe,
    Key,
    Link,
    Monitor,
    Play,
    Server,
    Settings,
    Shield,
    Square,
    Users,
    XCircle
} from 'lucide-react';
import { useState } from 'react';

interface RustDeskConfig {
  serverType: 'public' | 'private' | 'custom';
  customServer: string;
  key: string;
  relayServer: string;
  port: number;
  autoStart: boolean;
  directIp: boolean;
}

interface ExecutionResult {
  success: boolean;
  message: string;
  connectionId?: string;
  serverUrl?: string;
  error?: string;
}

export function RustDesk() {
  const [isExecuting, setIsExecuting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<ExecutionResult | null>(null);
  const [buildType, setBuildType] = useState<'source' | 'binary'>('binary');
  const [platform, setPlatform] = useState<'windows' | 'linux' | 'macos'>('windows');
  const [config, setConfig] = useState<RustDeskConfig>({
    serverType: 'public',
    customServer: '',
    key: '',
    relayServer: '',
    port: 21116,
    autoStart: true,
    directIp: false
  });

  const handleExecute = async () => {
    setIsExecuting(true);
    setProgress(0);
    setResults(null);

    try {
      const progressSteps = [
        { step: 'Validating configuration...', progress: 10 },
        { step: 'Downloading dependencies...', progress: 20 },
        { step: 'Setting up build environment...', progress: 30 },
        { step: 'Compiling RustDesk source...', progress: 45 },
        { step: 'Building GUI components...', progress: 60 },
        { step: 'Configuring server settings...', progress: 75 },
        { step: 'Generating connection ID...', progress: 90 },
        { step: 'Finalizing deployment...', progress: 100 }
      ];

      for (const { step, progress } of progressSteps) {
        setProgress(progress);
        await new Promise(resolve => setTimeout(resolve, 600));
      }

      const mockResult: ExecutionResult = {
        success: true,
        message: 'RustDesk deployed successfully',
        connectionId: 'rustdesk-' + Math.random().toString(36).substr(2, 9),
        serverUrl: config.serverType === 'public' ? 'rs-sg.rustdesk.com' : config.customServer
      };

      setResults(mockResult);
    } catch (error) {
      console.error('Execution failed:', error);
      setResults({
        success: false,
        message: 'Deployment failed',
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

  const copyCommands = () => {
    const commands = generateCommands();
    navigator.clipboard.writeText(commands);
  };

  const generateCommands = () => {
    if (buildType === 'source') {
      if (platform === 'windows') {
        return `# RustDesk Source Build Commands
# Platform: Windows

# Install vcpkg
git clone https://github.com/microsoft/vcpkg
cd vcpkg
git checkout 2023.04.15
cd ..
vcpkg/bootstrap-vcpkg.bat
vcpkg/vcpkg install libvpx:x64-windows-static libyuv:x64-windows-static opus:x64-windows-static aom:x64-windows-static

# Set environment variable
set VCPKG_ROOT=%CD%\\\\vcpkg

# Build RustDesk
git clone --recurse-submodules https://github.com/rustdesk/rustdesk
cd rustdesk
cargo run --release`;
      } else if (platform === 'linux') {
        return `# RustDesk Source Build Commands
# Platform: Linux

# Install system dependencies
sudo apt install -y zip g++ gcc git curl wget nasm yasm libgtk-3-dev clang libxcb-randr0-dev libxdo-dev libxfixes-dev libxcb-shape0-dev libxcb-xfixes0-dev libasound2-dev libpulse-dev cmake make libclang-dev ninja-build libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libpam0g-dev

# Install vcpkg
git clone https://github.com/microsoft/vcpkg
cd vcpkg
git checkout 2023.04.15
cd ..
vcpkg/bootstrap-vcpkg.sh
export VCPKG_ROOT=$HOME/vcpkg
vcpkg/vcpkg install libvpx libyuv opus aom

# Build RustDesk
git clone --recurse-submodules https://github.com/rustdesk/rustdesk
cd rustdesk
cargo run --release`;
      } else {
        return `# RustDesk Source Build Commands
# Platform: macOS

# Install dependencies with Homebrew
brew install rust git nasm yasm cmake

# Install vcpkg
git clone https://github.com/microsoft/vcpkg
cd vcpkg
git checkout 2023.04.15
cd ..
vcpkg/bootstrap-vcpkg.sh
export VCPKG_ROOT=$HOME/vcpkg
vcpkg/vcpkg install libvpx libyuv opus aom

# Build RustDesk
git clone --recurse-submodules https://github.com/rustdesk/rustdesk
cd rustdesk
cargo run --release`;
      }
    } else {
      const filename = platform === 'windows' ? 'x64-sciter.exe' : platform === 'linux' ? 'x86_64.AppImage' : 'x64.dmg';
      const installCommands = platform === 'windows' ? '# Run installer\nrustdesk-x64-sciter.exe /S' : 
                             platform === 'linux' ? '# Make executable and run\nchmod +x rustdesk-x86_64.AppImage\n./rustdesk-x86_64.AppImage' :
                             '# Mount DMG and install\nhdiutil attach rustdesk-x64.dmg\nsudo cp -R /Volumes/RustDesk/RustDesk.app /Applications/\nhdiutil detach /Volumes/RustDesk';

      return `# RustDesk Binary Deployment

# Download latest release
wget https://github.com/rustdesk/rustdesk/releases/latest/download/rustdesk-${filename}

# Install/configure
${installCommands}

# Configure server settings
${config.serverType !== 'public' ? `rustdesk --key ${config.key} --relay-server ${config.relayServer}` : '# Using public server'}`;
    }
  };

  const exportCommands = () => {
    const commands = generateCommands();
    const filename = `rustdesk-${buildType}-${platform}.sh`;
    const blob = new Blob([commands], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Monitor className="h-5 w-5 text-orange-400" />
            <span>RustDesk Remote Desktop</span>
          </CardTitle>
          <CardDescription>
            Open-source remote desktop solution with self-hosting capabilities
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <Badge variant="outline" className="border-orange-600 text-orange-400">
              Cross-Platform
            </Badge>
            <Badge variant="outline" className="border-blue-600 text-blue-400">
              Open Source
            </Badge>
            <Badge variant="outline" className="border-green-600 text-green-400">
              Self-Hosted
            </Badge>
            <Badge variant="outline" className="border-purple-600 text-purple-400">
              End-to-End Encrypted
            </Badge>
          </div>
        </CardContent>
      </Card>

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
              <label htmlFor="rustdesk-build-type" className="text-sm font-medium">
                Build Type
              </label>
              <select
                id="rustdesk-build-type"
                value={buildType}
                onChange={(e) => setBuildType(e.target.value as 'source' | 'binary')}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Select build type for RustDesk deployment"
              >
                <option value="binary">Binary Deployment</option>
                <option value="source">Source Build</option>
              </select>
            </div>
            <div className="space-y-2">
              <label htmlFor="rustdesk-platform" className="text-sm font-medium">
                Target Platform
              </label>
              <select
                id="rustdesk-platform"
                value={platform}
                onChange={(e) => setPlatform(e.target.value as 'windows' | 'linux' | 'macos')}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Select target platform for RustDesk"
              >
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="macos">macOS</option>
              </select>
            </div>
            <div className="space-y-2">
              <label htmlFor="rustdesk-server-type" className="text-sm font-medium">
                Server Type
              </label>
              <select
                id="rustdesk-server-type"
                value={config.serverType}
                onChange={(e) => setConfig({...config, serverType: e.target.value as 'public' | 'private' | 'custom'})}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Select server type for RustDesk connection"
              >
                <option value="public">Public Server</option>
                <option value="private">Private Server</option>
                <option value="custom">Custom Server</option>
              </select>
            </div>
            <div className="space-y-2">
              <label htmlFor="rustdesk-custom-server" className="text-sm font-medium">
                Custom Server URL
              </label>
              <input
                id="rustdesk-custom-server"
                type="text"
                value={config.customServer}
                onChange={(e) => setConfig({...config, customServer: e.target.value})}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting || config.serverType !== 'custom'}
                aria-label="Custom server URL for RustDesk"
                placeholder="rs.example.com:21116"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="rustdesk-connection-key" className="text-sm font-medium">
                Connection Key
              </label>
              <input
                id="rustdesk-connection-key"
                type="password"
                value={config.key}
                onChange={(e) => setConfig({...config, key: e.target.value})}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Connection key for RustDesk server"
                placeholder="Enter connection key"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="rustdesk-relay-server" className="text-sm font-medium">
                Relay Server
              </label>
              <input
                id="rustdesk-relay-server"
                type="text"
                value={config.relayServer}
                onChange={(e) => setConfig({...config, relayServer: e.target.value})}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isExecuting}
                aria-label="Relay server for RustDesk connections"
                placeholder="relay.example.com:21117"
              />
            </div>
          </div>
          
          <div className="flex items-center space-x-4">
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={config.autoStart}
                onChange={(e) => setConfig({...config, autoStart: e.target.checked})}
                disabled={isExecuting}
                className="rounded"
              />
              <span className="text-sm">Auto-start with system</span>
            </label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={config.directIp}
                onChange={(e) => setConfig({...config, directIp: e.target.checked})}
                disabled={isExecuting}
                className="rounded"
              />
              <span className="text-sm">Allow direct IP connections</span>
            </label>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Deployment Controls</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <Button
              onClick={handleExecute}
              disabled={isExecuting}
              className="bg-orange-600 hover:bg-orange-700"
              aria-label="Deploy RustDesk with current configuration"
            >
              <Play className="mr-2 h-4 w-4" />
              {isExecuting ? 'Deploying...' : 'Deploy RustDesk'}
            </Button>
            <Button
              onClick={handleStop}
              disabled={!isExecuting}
              variant="destructive"
              aria-label="Stop the current RustDesk deployment"
            >
              <Square className="mr-2 h-4 w-4" />
              Stop
            </Button>
            <Button
              onClick={copyCommands}
              disabled={isExecuting}
              variant="outline"
              aria-label="Copy deployment commands to clipboard"
            >
              Copy Commands
            </Button>
            <Button
              onClick={exportCommands}
              disabled={isExecuting}
              variant="outline"
              aria-label="Export deployment commands as a file"
            >
              <Download className="mr-2 h-4 w-4" />
              Export Script
            </Button>
          </div>

          {isExecuting && (
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-sm">
                <span>Deployment Progress</span>
                <span>{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
        </CardContent>
      </Card>

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
                <span>Deployment Results</span>
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
                
                <div className="grid gap-4 md:grid-cols-2 text-sm">
                  <div>
                    <span className="text-muted-foreground">Connection ID:</span>
                    <span className="ml-2 font-mono font-medium text-orange-400">
                      {results.connectionId}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Server:</span>
                    <span className="ml-2 font-medium">{results.serverUrl}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Platform:</span>
                    <span className="ml-2 font-medium">{platform}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Build Type:</span>
                    <span className="ml-2 font-medium">{buildType}</span>
                  </div>
                </div>

                <div className="p-4 bg-blue-50 dark:bg-blue-950 rounded-lg">
                  <p className="text-xs text-blue-800 dark:text-blue-200">
                    <strong>Next Steps:</strong> Download the RustDesk client and connect using the provided Connection ID. 
                    Configure your firewall to allow connections on port {config.port}.
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

      <Card>
        <CardHeader>
          <CardTitle>Generated Commands ({platform} - {buildType})</CardTitle>
          <CardDescription>
            Deployment commands for the target platform
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="bg-muted rounded-lg p-4">
            <pre className="text-xs font-mono whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
              {generateCommands()}
            </pre>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Globe className="h-5 w-5" />
            <span>RustDesk Features</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <div className="flex items-start space-x-3">
              <Shield className="h-5 w-5 text-green-400 mt-0.5" />
              <div>
                <h4 className="font-medium">End-to-End Encryption</h4>
                <p className="text-sm text-muted-foreground">All connections are encrypted with TLS</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Server className="h-5 w-5 text-blue-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Self-Hosting</h4>
                <p className="text-sm text-muted-foreground">Deploy your own relay server</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Users className="h-5 w-5 text-purple-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Multi-User Support</h4>
                <p className="text-sm text-muted-foreground">Share access with team members</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Link className="h-5 w-5 text-orange-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Direct IP Connection</h4>
                <p className="text-sm text-muted-foreground">Connect without relay servers</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Monitor className="h-5 w-5 text-cyan-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Cross-Platform</h4>
                <p className="text-sm text-muted-foreground">Windows, Linux, macOS support</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Key className="h-5 w-5 text-yellow-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Access Control</h4>
                <p className="text-sm text-muted-foreground">Password and key-based authentication</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Deployment Terminal</CardTitle>
          <CardDescription>
            Real-time deployment output and debugging information
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Terminal readOnly />
        </CardContent>
      </Card>
    </div>
  );
}
