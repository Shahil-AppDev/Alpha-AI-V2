'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Terminal } from '@/components/ui/terminal';
import { 
  Code, 
  Play, 
  AlertTriangle, 
  Shield,
  Bug,
  Lock,
  Eye,
  Download
} from 'lucide-react';

interface Vulnerability {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  line: number;
  code_snippet: string;
  description: string;
  recommendation: string;
}

interface AnalysisResult {
  success: boolean;
  vulnerabilities_found: number;
  vulnerabilities: Vulnerability[];
  llm_analysis_used: boolean;
  analysis_summary: {
    total_vulnerabilities: number;
    severity_breakdown: Record<string, number>;
    most_critical: boolean;
    requires_immediate_attention: boolean;
  };
}

export function CodeAnalysis() {
  const [codeInput, setCodeInput] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<AnalysisResult | null>(null);
  const [useLLM, setUseLLM] = useState(false);

  const sampleCode = `import os
import subprocess
from flask import Flask, request

app = Flask(__name__)
debug = True

@app.route('/login')
def login():
    password = "admin123"
    api_key = "sk-1234567890abcdef"
    
    user_input = request.args.get('user')
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    
    os.system("ls -la " + user_input)
    subprocess.call(["rm", "-rf", "/tmp/" + user_input], shell=True)
    
    return "Hello"`;

  const handleAnalyze = async () => {
    if (!codeInput.trim()) return;

    setIsAnalyzing(true);
    
    try {
      // Simulate API call to backend
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Mock analysis results
      const mockResults: AnalysisResult = {
        success: true,
        vulnerabilities_found: 5,
        vulnerabilities: [
          {
            type: 'Hardcoded Password',
            severity: 'high',
            line: 8,
            code_snippet: 'password = "admin123"',
            description: 'Hardcoded password detected in source code',
            recommendation: 'Move secrets to environment variables or secure configuration files'
          },
          {
            type: 'Hardcoded API Key',
            severity: 'high',
            line: 9,
            code_snippet: 'api_key = "sk-1234567890abcdef"',
            description: 'Hardcoded API key detected',
            recommendation: 'Use secure key management system'
          },
          {
            type: 'SQL Injection',
            severity: 'critical',
            line: 13,
            code_snippet: 'query = "SELECT * FROM users WHERE name = \'" + user_input + "\'"',
            description: 'SQL query built with string concatenation',
            recommendation: 'Use parameterized queries or prepared statements'
          },
          {
            type: 'Command Injection',
            severity: 'critical',
            line: 15,
            code_snippet: 'os.system("ls -la " + user_input)',
            description: 'os.system() called with concatenated user input',
            recommendation: 'Avoid shell=True, validate input, use whitelist approach'
          },
          {
            type: 'Debug Mode Enabled',
            severity: 'medium',
            line: 6,
            code_snippet: 'debug = True',
            description: 'Debug mode enabled in production',
            recommendation: 'Disable debug mode in production environments'
          }
        ],
        llm_analysis_used: useLLM,
        analysis_summary: {
          total_vulnerabilities: 5,
          severity_breakdown: {
            critical: 2,
            high: 2,
            medium: 1,
            low: 0
          },
          most_critical: true,
          requires_immediate_attention: true
        }
      };

      setResults(mockResults);
    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const loadSampleCode = () => {
    setCodeInput(sampleCode);
  };

  const clearResults = () => {
    setResults(null);
    setCodeInput('');
  };

  const exportResults = () => {
    if (!results) return;
    
    const data = JSON.stringify(results, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `code-analysis-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-security-red bg-red-50 dark:bg-red-950 border-red-200';
      case 'high': return 'text-security-orange bg-orange-50 dark:bg-orange-950 border-orange-200';
      case 'medium': return 'text-security-yellow bg-yellow-50 dark:bg-yellow-950 border-yellow-200';
      case 'low': return 'text-security-green bg-green-50 dark:bg-green-950 border-green-200';
      default: return 'text-gray-600 bg-gray-50 dark:bg-gray-950 border-gray-200';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="h-4 w-4" />;
      case 'high': return <Bug className="h-4 w-4" />;
      case 'medium': return <Shield className="h-4 w-4" />;
      case 'low': return <Eye className="h-4 w-4" />;
      default: return <Lock className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Code Input */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Code className="h-5 w-5" />
            <span>Code Analysis</span>
          </CardTitle>
          <CardDescription>
            Analyze code snippets for security vulnerabilities using static analysis and LLM
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Code Snippet</label>
            <textarea
              value={codeInput}
              onChange={(e) => setCodeInput(e.target.value)}
              placeholder="Paste your code here for security analysis..."
              className="w-full h-64 px-3 py-2 border border-input rounded-md bg-background font-mono text-sm"
              disabled={isAnalyzing}
            />
          </div>

          <div className="flex items-center space-x-4">
            <label className="flex items-center space-x-2 text-sm">
              <input
                type="checkbox"
                checked={useLLM}
                onChange={(e) => setUseLLM(e.target.checked)}
                disabled={isAnalyzing}
              />
              <span>Use LLM Analysis (Advanced)</span>
            </label>
            <Button
              variant="outline"
              size="sm"
              onClick={loadSampleCode}
              disabled={isAnalyzing}
            >
              Load Sample Code
            </Button>
          </div>

          <div className="flex items-center space-x-2">
            <Button
              onClick={handleAnalyze}
              disabled={isAnalyzing || !codeInput.trim()}
              className="security-button"
            >
              <Play className="mr-2 h-4 w-4" />
              {isAnalyzing ? 'Analyzing...' : 'Analyze Code'}
            </Button>
            <Button
              onClick={clearResults}
              variant="outline"
              disabled={isAnalyzing}
            >
              Clear
            </Button>
            {results && (
              <Button
                onClick={exportResults}
                variant="outline"
              >
                <Download className="mr-2 h-4 w-4" />
                Export
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Analysis Results */}
      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Analysis Results</span>
              <div className="flex items-center space-x-2">
                <Badge variant={results.analysis_summary.most_critical ? 'destructive' : 'success'}>
                  {results.vulnerabilities_found} vulnerabilities found
                </Badge>
                {results.llm_analysis_used && (
                  <Badge variant="secondary">LLM Enhanced</Badge>
                )}
              </div>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {/* Summary */}
            <div className="mb-6 p-4 bg-muted rounded-lg">
              <h4 className="font-medium mb-3">Summary</h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Critical:</span>
                  <span className="ml-2 font-medium text-security-red">
                    {results.analysis_summary.severity_breakdown.critical}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">High:</span>
                  <span className="ml-2 font-medium text-security-orange">
                    {results.analysis_summary.severity_breakdown.high}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Medium:</span>
                  <span className="ml-2 font-medium text-security-yellow">
                    {results.analysis_summary.severity_breakdown.medium}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Low:</span>
                  <span className="ml-2 font-medium text-security-green">
                    {results.analysis_summary.severity_breakdown.low}
                  </span>
                </div>
              </div>
            </div>

            {/* Vulnerabilities */}
            <div className="space-y-4">
              {results.vulnerabilities.map((vuln, index) => (
                <div key={index} className={`border rounded-lg p-4 ${getSeverityColor(vuln.severity)}`}>
                  <div className="flex items-start space-x-3">
                    <div className="flex-shrink-0 mt-1">
                      {getSeverityIcon(vuln.severity)}
                    </div>
                    <div className="flex-1 space-y-2">
                      <div className="flex items-center justify-between">
                        <h4 className="font-medium">{vuln.type}</h4>
                        <Badge variant="outline" className="capitalize">
                          {vuln.severity}
                        </Badge>
                      </div>
                      
                      <p className="text-sm text-muted-foreground">
                        {vuln.description}
                      </p>
                      
                      <div className="bg-background rounded p-2">
                        <p className="text-xs font-mono text-security-red">
                          Line {vuln.line}: {vuln.code_snippet}
                        </p>
                      </div>
                      
                      <div className="bg-blue-50 dark:bg-blue-950 rounded p-2">
                        <p className="text-xs">
                          <strong>Recommendation:</strong> {vuln.recommendation}
                        </p>
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
          <CardTitle>Analysis Terminal</CardTitle>
          <CardDescription>
            Detailed analysis output and debugging information
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Terminal readOnly />
        </CardContent>
      </Card>
    </div>
  );
}
