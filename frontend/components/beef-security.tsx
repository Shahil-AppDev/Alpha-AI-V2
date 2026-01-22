'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Terminal } from '@/components/ui/terminal';
import {
    AlertTriangle,
    Bug,
    CheckCircle,
    Download,
    Eye,
    Globe,
    Info,
    Lock,
    Monitor,
    Play,
    Settings,
    Shield,
    Square,
    Target,
    Users,
    XCircle,
    Zap
} from 'lucide-react';
import { useState } from 'react';

interface BeefConfig {
  targetUrl: string;
  enableXss: boolean;
  enableCsrf: boolean;
  enableNetworkAnalysis: boolean;
  enableBrowserInfo: boolean;
  sessionTimeout: number;
  maxHooks: number;
}

interface BeefResult {
  success: boolean;
  message: string;
  sessionId?: string;
  hookUrl?: string;
  hookedBrowsers?: Array<{
    id: string;
    ip: string;
    browser: string;
    os: string;
    hookedAt: string;
  }>;
  vulnerabilities?: Array<{
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    evidence: string;
  }>;
  statistics?: {
    totalHooks: number;
    activeHooks: number;
    commandsExecuted: number;
    dataExfiltrated: number;
  };
  error?: string;
}

export function BeefSecurity() {
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<BeefResult | null>(null);
  const [config, setConfig] = useState<BeefConfig>({
    targetUrl: '',
    enableXss: true,
    enableCsrf: true,
    enableNetworkAnalysis: true,
    enableBrowserInfo: true,
    sessionTimeout: 3600,
    maxHooks: 10
  });

  const handleStartBeef = async () => {
    if (!config.targetUrl.trim()) {
      setResults({
        success: false,
        message: 'Please provide a target URL for security testing',
        error: 'Target URL is required'
      });
      return;
    }

    // Validate URL format
    try {
      new URL(config.targetUrl);
    } catch {
      setResults({
        success: false,
        message: 'Please provide a valid URL (e.g., https://example.com)',
        error: 'Invalid URL format'
      });
      return;
    }

    setIsRunning(true);
    setProgress(0);
    setResults(null);

    try {
      // Simulate BeEF startup process
      const startupSteps = [
        { step: 'Starting BeEF server...', progress: 10 },
        { step: 'Initializing security modules...', progress: 20 },
        { step: 'Configuring hook points...', progress: 30 },
        { step: 'Setting up XSS detection...', progress: 40 },
        { step: 'Configuring CSRF protection...', progress: 50 },
        { step: 'Enabling network analysis...', progress: 60 },
        { step: 'Generating hook URL...', progress: 70 },
        { step: 'Starting browser monitoring...', progress: 80 },
        { step: 'Initializing security checks...', progress: 90 },
        { step: 'BeEF server ready!', progress: 100 }
      ];

      for (const { progress } of startupSteps) {
        setProgress(progress);
        await new Promise(resolve => setTimeout(resolve, 400));
      }

      // Mock BeEF results for security testing
      const mockResults: BeefResult = {
        success: true,
        message: 'BeEF security testing server started successfully',
        sessionId: 'beef-session-' + Math.random().toString(36).substr(2, 9),
        hookUrl: `http://localhost:3000/hook.js?session=${Math.random().toString(36).substr(2, 9)}`,
        hookedBrowsers: [],
        vulnerabilities: [
          {
            type: 'XSS Vulnerability',
            severity: 'medium',
            description: 'Potential cross-site scripting vulnerability detected',
            evidence: 'Reflected input in response without proper encoding'
          },
          {
            type: 'CSRF Protection',
            severity: 'low',
            description: 'CSRF tokens should be implemented for sensitive operations',
            evidence: 'Missing anti-CSRF tokens in form submissions'
          },
          {
            type: 'Information Disclosure',
            severity: 'low',
            description: 'Server information exposed in headers',
            evidence: 'Server version and technology stack visible'
          }
        ],
        statistics: {
          totalHooks: 0,
          activeHooks: 0,
          commandsExecuted: 0,
          dataExfiltrated: 0
        }
      };

      setResults(mockResults);
    } catch (error) {
      console.error('BeEF startup failed:', error);
      setResults({
        success: false,
        message: 'Failed to start BeEF security testing',
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
    } finally {
      setIsRunning(false);
      setProgress(0);
    }
  };

  const handleStopBeef = () => {
    setIsRunning(false);
    setProgress(0);
    setResults({
      success: false,
      message: 'BeEF security testing stopped',
      error: 'Server stopped by user'
    });
  };

  const generateHookCode = () => {
    if (!results?.hookUrl) return '';
    
    return `<script src="${results.hookUrl}"></script>`;
  };

  const copyHookCode = () => {
    const hookCode = generateHookCode();
    navigator.clipboard.writeText(hookCode);
  };

  const exportReport = () => {
    if (!results) return;
    
    const reportData = {
      timestamp: new Date().toISOString(),
      config,
      results,
      securityAssessment: 'Educational security testing only'
    };
    
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'beef-security-report.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-orange-600';
      case 'medium': return 'bg-yellow-600';
      case 'low': return 'bg-blue-600';
      default: return 'bg-gray-600';
    }
  };

  return (
    <div className="space-y-6">
      {/* Tool Header */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="h-5 w-5 text-green-400" />
            <span>BeEF Security Testing</span>
          </CardTitle>
          <CardDescription>
            Browser Exploitation Framework for educational security testing and awareness training
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <Badge variant="outline" className="border-green-600 text-green-400">
              Educational
            </Badge>
            <Badge variant="outline" className="border-blue-600 text-blue-400">
              Browser Security
            </Badge>
            <Badge variant="outline" className="border-orange-600 text-orange-400">
              XSS Testing
            </Badge>
            <Badge variant="outline" className="border-purple-600 text-purple-400">
              Security Awareness
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Security Warning */}
      <Card className="border-yellow-600 bg-yellow-50/10">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2 text-yellow-400">
            <AlertTriangle className="h-5 w-5" />
            <span>Security Notice</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            <p className="text-yellow-200">
              <strong>For Educational and Authorized Testing Only</strong>
            </p>
            <ul className="list-disc list-inside text-yellow-300 space-y-1">
              <li>Only use on systems you own or have explicit permission to test</li>
              <li>Ensure compliance with all applicable laws and regulations</li>
              <li>This tool is designed for security awareness and training purposes</li>
              <li>Unauthorized use may violate computer crime and privacy laws</li>
            </ul>
          </div>
        </CardContent>
      </Card>

      {/* Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Settings className="h-5 w-5" />
            <span>Security Testing Configuration</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="target-url" className="text-sm font-medium">
              Target URL (for authorized testing)
            </label>
            <input
              id="target-url"
              type="url"
              value={config.targetUrl}
              onChange={(e) => setConfig({...config, targetUrl: e.target.value})}
              className="w-full px-3 py-2 border border-input rounded-md bg-background"
              disabled={isRunning}
              placeholder="https://example.com (authorized target only)"
            />
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-3">
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.enableXss}
                  onChange={(e) => setConfig({...config, enableXss: e.target.checked})}
                  disabled={isRunning}
                  className="rounded"
                />
                <span className="text-sm">Enable XSS Detection</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.enableCsrf}
                  onChange={(e) => setConfig({...config, enableCsrf: e.target.checked})}
                  disabled={isRunning}
                  className="rounded"
                />
                <span className="text-sm">Enable CSRF Testing</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.enableNetworkAnalysis}
                  onChange={(e) => setConfig({...config, enableNetworkAnalysis: e.target.checked})}
                  disabled={isRunning}
                  className="rounded"
                />
                <span className="text-sm">Enable Network Analysis</span>
              </label>
            </div>
            <div className="space-y-3">
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.enableBrowserInfo}
                  onChange={(e) => setConfig({...config, enableBrowserInfo: e.target.checked})}
                  disabled={isRunning}
                  className="rounded"
                />
                <span className="text-sm">Enable Browser Info</span>
              </label>
              <div className="space-y-2">
                <label htmlFor="session-timeout" className="text-sm font-medium">Session Timeout (seconds)</label>
                <input
                  id="session-timeout"
                  type="number"
                  value={config.sessionTimeout}
                  onChange={(e) => setConfig({...config, sessionTimeout: parseInt(e.target.value) || 3600})}
                  disabled={isRunning}
                  className="w-full px-3 py-2 border border-input rounded-md bg-background"
                  min="60"
                  max="86400"
                  placeholder="3600"
                  title="Session timeout in seconds (60-86400)"
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="max-hooks" className="text-sm font-medium">Max Hooked Browsers</label>
                <input
                  id="max-hooks"
                  type="number"
                  value={config.maxHooks}
                  onChange={(e) => setConfig({...config, maxHooks: parseInt(e.target.value) || 10})}
                  disabled={isRunning}
                  className="w-full px-3 py-2 border border-input rounded-md bg-background"
                  min="1"
                  max="100"
                  placeholder="10"
                  title="Maximum number of browsers that can be hooked (1-100)"
                />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Controls */}
      <Card>
        <CardHeader>
          <CardTitle>Security Testing Controls</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <Button
              onClick={handleStartBeef}
              disabled={isRunning || !config.targetUrl.trim()}
              className="bg-green-600 hover:bg-green-700"
            >
              <Play className="mr-2 h-4 w-4" />
              {isRunning ? 'Starting...' : 'Start Security Testing'}
            </Button>
            <Button
              onClick={handleStopBeef}
              disabled={!isRunning}
              variant="destructive"
            >
              <Square className="mr-2 h-4 w-4" />
              Stop Testing
            </Button>
            <Button
              onClick={copyHookCode}
              disabled={!results?.hookUrl || isRunning}
              variant="outline"
            >
              Copy Hook Code
            </Button>
            <Button
              onClick={exportReport}
              disabled={!results || isRunning}
              variant="outline"
            >
              <Download className="mr-2 h-4 w-4" />
              Export Report
            </Button>
          </div>

          {isRunning && (
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-sm">
                <span>Starting BeEF Server</span>
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
                <span>Security Testing Results</span>
              </span>
              <Badge variant={results.success ? 'success' : 'destructive'}>
                {results.success ? 'Active' : 'Stopped'}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {results.success ? (
              <div className="space-y-6">
                <div className="p-4 bg-green-50 dark:bg-green-950 rounded-lg">
                  <p className="text-sm font-medium text-green-800 dark:text-green-200">
                    {results.message}
                  </p>
                </div>

                {/* Hook Information */}
                {results.hookUrl && (
                  <div>
                    <h4 className="text-lg font-semibold mb-3 flex items-center">
                      <Bug className="h-5 w-5 mr-2 text-blue-400" />
                      Hook Information
                    </h4>
                    <div className="space-y-2">
                      <div className="p-3 bg-muted rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium">Hook URL:</span>
                          <Button
                            onClick={copyHookCode}
                            variant="outline"
                            size="sm"
                          >
                            Copy Code
                          </Button>
                        </div>
                        <code className="text-xs font-mono break-all">
                          {generateHookCode()}
                        </code>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        <p>Add this script to your authorized test page to hook browsers for security analysis.</p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Vulnerabilities Found */}
                {results.vulnerabilities && results.vulnerabilities.length > 0 && (
                  <div>
                    <h4 className="text-lg font-semibold mb-3 flex items-center">
                      <AlertTriangle className="h-5 w-5 mr-2 text-orange-400" />
                      Security Issues Detected
                    </h4>
                    <div className="space-y-2">
                      {results.vulnerabilities.map((vuln, index) => (
                        <div key={index} className="p-3 bg-orange-50 dark:bg-orange-950 rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-medium text-sm">{vuln.type}</span>
                            <Badge variant="outline" className={`text-xs ${getSeverityColor(vuln.severity)}`}>
                              {vuln.severity.toUpperCase()}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mb-1">{vuln.description}</p>
                          <p className="text-xs text-muted-foreground">
                            <strong>Evidence:</strong> {vuln.evidence}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Statistics */}
                {results.statistics && (
                  <div>
                    <h4 className="text-lg font-semibold mb-3 flex items-center">
                      <Monitor className="h-5 w-5 mr-2 text-purple-400" />
                      Testing Statistics
                    </h4>
                    <div className="grid gap-4 md:grid-cols-2 text-sm">
                      <div className="flex items-center space-x-2">
                        <Users className="h-4 w-4 text-gray-400" />
                        <span className="text-muted-foreground">Total Hooks:</span>
                        <span className="font-medium">{results.statistics.totalHooks}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Eye className="h-4 w-4 text-gray-400" />
                        <span className="text-muted-foreground">Active Hooks:</span>
                        <span className="font-medium">{results.statistics.activeHooks}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Zap className="h-4 w-4 text-gray-400" />
                        <span className="text-muted-foreground">Commands Executed:</span>
                        <span className="font-medium">{results.statistics.commandsExecuted}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Target className="h-4 w-4 text-gray-400" />
                        <span className="text-muted-foreground">Data Analyzed:</span>
                        <span className="font-medium">{results.statistics.dataExfiltrated} bytes</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Hooked Browsers */}
                {results.hookedBrowsers && results.hookedBrowsers.length > 0 && (
                  <div>
                    <h4 className="text-lg font-semibold mb-3 flex items-center">
                      <Monitor className="h-5 w-5 mr-2 text-blue-400" />
                      Hooked Browsers
                    </h4>
                    <div className="space-y-2">
                      {results.hookedBrowsers.map((browser, index) => (
                        <div key={index} className="p-3 bg-blue-50 dark:bg-blue-950 rounded-lg">
                          <div className="flex items-center justify-between">
                            <span className="font-medium text-sm">Browser {index + 1}</span>
                            <Badge variant="outline" className="text-xs border-blue-600 text-blue-400">
                              Active
                            </Badge>
                          </div>
                          <div className="text-xs text-muted-foreground mt-1">
                            <p>IP: {browser.ip}</p>
                            <p>Browser: {browser.browser}</p>
                            <p>OS: {browser.os}</p>
                            <p>Hooked: {browser.hookedAt}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
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

      {/* Educational Information */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Info className="h-5 w-5 text-blue-400" />
            <span>Educational Security Testing</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              <div className="flex items-start space-x-3">
                <Shield className="h-5 w-5 text-green-400 mt-0.5" />
                <div>
                  <h4 className="font-medium">Security Awareness</h4>
                  <p className="text-sm text-muted-foreground">Educational tool for understanding browser security risks</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <Bug className="h-5 w-5 text-orange-400 mt-0.5" />
                <div>
                  <h4 className="font-medium">XSS Testing</h4>
                  <p className="text-sm text-muted-foreground">Demonstrates cross-site scripting vulnerabilities</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <Lock className="h-5 w-5 text-blue-400 mt-0.5" />
                <div>
                  <h4 className="font-medium">CSRF Protection</h4>
                  <p className="text-sm text-muted-foreground">Tests cross-site request forgery protections</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <Globe className="h-5 w-5 text-purple-400 mt-0.5" />
                <div>
                  <h4 className="font-medium">Browser Analysis</h4>
                  <p className="text-sm text-muted-foreground">Analyzes browser capabilities and information</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <Monitor className="h-5 w-5 text-cyan-400 mt-0.5" />
                <div>
                  <h4 className="font-medium">Real-time Monitoring</h4>
                  <p className="text-sm text-muted-foreground">Monitors browser interactions in real-time</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <Target className="h-5 w-5 text-red-400 mt-0.5" />
                <div>
                  <h4 className="font-medium">Targeted Testing</h4>
                  <p className="text-sm text-muted-foreground">Focused security assessment capabilities</p>
                </div>
              </div>
            </div>
            
            <div className="p-4 bg-blue-50 dark:bg-blue-950 rounded-lg">
              <h4 className="font-medium text-blue-800 dark:text-blue-200 mb-2">
                Educational Purpose Only
              </h4>
              <p className="text-sm text-blue-700 dark:text-blue-300">
                This BeEF integration is designed for educational security testing and awareness training only. 
                Always ensure you have proper authorization before testing any system and comply with all applicable laws and regulations.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Terminal Output */}
      <Card>
        <CardHeader>
          <CardTitle>Security Testing Terminal</CardTitle>
          <CardDescription>
            Real-time output from BeEF security testing operations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Terminal readOnly />
        </CardContent>
      </Card>
    </div>
  );
}
