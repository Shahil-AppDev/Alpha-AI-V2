'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Terminal } from '@/components/ui/terminal';
import { 
  Network, 
  Play, 
  Square, 
  Download,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle
} from 'lucide-react';

interface ScanResult {
  ip: string;
  ports: number[];
  services: Record<number, string>;
  status: 'open' | 'closed' | 'filtered';
  vulnerabilities: string[];
}

interface NetworkScanProps {
  className?: string;
}

export function NetworkScan({ className }: NetworkScanProps) {
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [scanType, setScanType] = useState<'quick' | 'comprehensive'>('quick');

  const handleScan = async () => {
    if (!target.trim()) return;

    setIsScanning(true);
    setProgress(0);
    setResults([]);

    try {
      // Simulate scan progress
      for (let i = 0; i <= 100; i += 10) {
        setProgress(i);
        await new Promise(resolve => setTimeout(resolve, 200));
      }

      // Mock scan results
      const mockResults: ScanResult[] = [
        {
          ip: target,
          ports: [22, 80, 443, 8080],
          services: {
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-Alt'
          },
          status: 'open',
          vulnerabilities: ['SSH version 7.4 vulnerable to CVE-2016-0777', 'HTTP server exposes version information']
        },
        {
          ip: `${target}.1`,
          ports: [80, 443],
          services: {
            80: 'HTTP',
            443: 'HTTPS'
          },
          status: 'open',
          vulnerabilities: ['SSL certificate expires soon']
        }
      ];

      setResults(mockResults);
    } catch (error) {
      console.error('Scan failed:', error);
    } finally {
      setIsScanning(false);
      setProgress(0);
    }
  };

  const handleStop = () => {
    setIsScanning(false);
    setProgress(0);
  };

  const exportResults = () => {
    const data = JSON.stringify(results, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-results-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityBadge = (vulnerabilities: string[]) => {
    if (vulnerabilities.length === 0) {
      return <Badge variant="success">Secure</Badge>;
    } else if (vulnerabilities.length <= 2) {
      return <Badge variant="warning">Low Risk</Badge>;
    } else {
      return <Badge variant="destructive">High Risk</Badge>;
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Scan Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Network className="h-5 w-5" />
            <span>Network Scanner</span>
          </CardTitle>
          <CardDescription>
            Scan networks and hosts for open ports, services, and vulnerabilities
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <label className="text-sm font-medium">Target</label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.1.1 or 192.168.1.0/24"
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isScanning}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Scan Type</label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value as 'quick' | 'comprehensive')}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isScanning}
              >
                <option value="quick">Quick Scan (Common Ports)</option>
                <option value="comprehensive">Comprehensive Scan (All Ports)</option>
              </select>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <Button
              onClick={handleScan}
              disabled={isScanning || !target.trim()}
              className="security-button"
            >
              <Play className="mr-2 h-4 w-4" />
              {isScanning ? 'Scanning...' : 'Start Scan'}
            </Button>
            <Button
              onClick={handleStop}
              disabled={!isScanning}
              variant="destructive"
            >
              <Square className="mr-2 h-4 w-4" />
              Stop
            </Button>
            <Button
              onClick={exportResults}
              disabled={results.length === 0}
              variant="outline"
            >
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
          </div>

          {isScanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Scan Progress</span>
                <span>{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan Results */}
      {results.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Scan Results</span>
              <Badge variant="outline">{results.length} hosts found</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {results.map((result, index) => (
                <div key={index} className="border rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Shield className="h-4 w-4" />
                      <span className="font-medium">{result.ip}</span>
                      <Badge variant="outline">{result.ports.length} ports</Badge>
                    </div>
                    {getSeverityBadge(result.vulnerabilities)}
                  </div>

                  <div className="grid gap-2 md:grid-cols-2">
                    <div>
                      <h4 className="text-sm font-medium mb-2">Open Ports & Services</h4>
                      <div className="space-y-1">
                        {result.ports.map(port => (
                          <div key={port} className="flex items-center space-x-2 text-sm">
                            <CheckCircle className="h-3 w-3 text-security-green" />
                            <span>{port}</span>
                            <span className="text-muted-foreground">({result.services[port]})</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h4 className="text-sm font-medium mb-2">Vulnerabilities</h4>
                      <div className="space-y-1">
                        {result.vulnerabilities.length > 0 ? (
                          result.vulnerabilities.map((vuln, i) => (
                            <div key={i} className="flex items-start space-x-2 text-sm">
                              <AlertTriangle className="h-3 w-3 text-security-orange mt-0.5" />
                              <span>{vuln}</span>
                            </div>
                          ))
                        ) : (
                          <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                            <CheckCircle className="h-3 w-3" />
                            <span>No vulnerabilities detected</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Terminal Output */}
      <Card>
        <CardHeader>
          <CardTitle>Terminal Output</CardTitle>
          <CardDescription>
            Real-time scan progress and detailed output
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Terminal readOnly />
        </CardContent>
      </Card>
    </div>
  );
}
