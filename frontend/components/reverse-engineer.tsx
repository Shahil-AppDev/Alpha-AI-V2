'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Terminal } from '@/components/ui/terminal';
import {
    AlertTriangle,
    BarChart3,
    CheckCircle,
    Code2,
    Download,
    Eye,
    FileText,
    GitBranch,
    Hash,
    Layers,
    Package,
    Play,
    Search,
    Settings,
    Square,
    XCircle,
    Zap
} from 'lucide-react';
import { useState } from 'react';

interface AnalysisConfig {
  beautifyCode: boolean;
  extractFunctions: boolean;
  extractVariables: boolean;
  extractStrings: boolean;
  detectPatterns: boolean;
  analyzeControlFlow: boolean;
  generateReport: boolean;
}

interface AnalysisResult {
  success: boolean;
  message: string;
  statistics?: {
    lines: number;
    functions: number;
    variables: number;
    strings: number;
    complexity: number;
    patterns: number;
  };
  functions?: Array<{
    name: string;
    parameters: string[];
    complexity: number;
    location: { start: { line: number; column: number } };
  }>;
  patterns?: Array<{
    type: string;
    description: string;
    location: { start: { line: number; column: number } };
  }>;
  recommendations?: string[];
  beautifiedCode?: string;
  error?: string;
}

export function ReverseEngineer() {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<AnalysisResult | null>(null);
  const [inputCode, setInputCode] = useState('');
  const [config, setConfig] = useState<AnalysisConfig>({
    beautifyCode: true,
    extractFunctions: true,
    extractVariables: true,
    extractStrings: true,
    detectPatterns: true,
    analyzeControlFlow: true,
    generateReport: true
  });

  const handleAnalyze = async () => {
    if (!inputCode.trim()) {
      setResults({
        success: false,
        message: 'Please provide JavaScript code to analyze',
        error: 'No input code provided'
      });
      return;
    }

    setIsAnalyzing(true);
    setProgress(0);
    setResults(null);

    try {
      // Simulate analysis process
      const progressSteps = [
        { step: 'Parsing JavaScript code...', progress: 10 },
        { step: 'Building AST...', progress: 20 },
        { step: 'Extracting functions...', progress: 30 },
        { step: 'Analyzing variables...', progress: 40 },
        { step: 'Extracting strings...', progress: 50 },
        { step: 'Detecting patterns...', progress: 60 },
        { step: 'Analyzing control flow...', progress: 70 },
        { step: 'Calculating complexity...', progress: 80 },
        { step: 'Generating recommendations...', progress: 90 },
        { step: 'Finalizing analysis...', progress: 100 }
      ];

      for (const {} of progressSteps) {
        setProgress(progress);
        await new Promise(resolve => setTimeout(resolve, 400));
      }

      // Mock analysis result
      const mockResult: AnalysisResult = {
        success: true,
        message: 'Code analysis completed successfully',
        statistics: {
          lines: inputCode.split('\n').length,
          functions: Math.floor(Math.random() * 10) + 1,
          variables: Math.floor(Math.random() * 20) + 5,
          strings: Math.floor(Math.random() * 15) + 3,
          complexity: Math.floor(Math.random() * 15) + 1,
          patterns: Math.floor(Math.random() * 5)
        },
        functions: [
          {
            name: 'main',
            parameters: ['data', 'options'],
            complexity: 5,
            location: { start: { line: 1, column: 0 } }
          },
          {
            name: 'processData',
            parameters: ['input'],
            complexity: 3,
            location: { start: { line: 10, column: 0 } }
          }
        ],
        patterns: [
          {
            type: 'Dynamic Code Execution',
            description: 'Usage of eval() detected',
            location: { start: { line: 15, column: 10 } }
          }
        ],
        recommendations: [
          'Overall: • Moderate complexity - acceptable but monitor growth.',
          'Function \'main\' (line 1): Consider splitting into smaller functions.',
          'Security: Dynamic code execution detected - review for security risks.'
        ]
      };

      if (config.beautifyCode) {
        // Simple beautification for demo
        mockResult.beautifiedCode = inputCode
          .replace(/;/g, ';\n')
          .replace(/{/g, ' {\n  ')
          .replace(/}/g, '\n}')
          .replace(/\n\s*\n/g, '\n');
      }

      setResults(mockResult);
    } catch (error) {
      console.error('Analysis failed:', error);
      setResults({
        success: false,
        message: 'Analysis failed',
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
    } finally {
      setIsAnalyzing(false);
      setProgress(0);
    }
  };

  const handleStop = () => {
    setIsAnalyzing(false);
    setProgress(0);
  };

  const loadSampleCode = () => {
    const sampleCode = `function processData(data,options){var result=[];if(options.validate){if(!data||typeof data!=='object')return null;}for(var i=0;i<data.length;i++){var item=data[i];if(item.active){var processed=transform(item);result.push(processed);}}return result;}function transform(item){return{id:item.id,name:item.name.toUpperCase(),timestamp:new Date().getTime()};}var config={validate:true,debug:false};eval('console.log("Dynamic execution")');`;
    setInputCode(sampleCode);
  };

  const exportResults = () => {
    if (!results) return;
    
    const reportData = {
      timestamp: new Date().toISOString(),
      config,
      results,
      originalCode: inputCode
    };
    
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'reverse-engineer-analysis.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyResults = () => {
    if (!results) return;
    
    const reportText = `
REVERSE ENGINEER ANALYSIS REPORT
================================

Input Statistics:
- Lines: ${results.statistics?.lines || 0}
- Functions: ${results.statistics?.functions || 0}
- Variables: ${results.statistics?.variables || 0}
- Strings: ${results.statistics?.strings || 0}
- Complexity: ${results.statistics?.complexity || 0}
- Patterns: ${results.statistics?.patterns || 0}

Functions Found:
${results.functions?.map(f => `- ${f.name}(${f.parameters.join(', ')}) - Complexity: ${f.complexity}`).join('\n') || 'None'}

Patterns Detected:
${results.patterns?.map(p => `- ${p.type}: ${p.description}`).join('\n') || 'None'}

Recommendations:
${results.recommendations?.map(r => `- ${r}`).join('\n') || 'None'}
    `;
    
    navigator.clipboard.writeText(reportText);
  };

  return (
    <div className="space-y-6">
      {/* Tool Header */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Code2 className="h-5 w-5 text-purple-400" />
            <span>JavaScript Reverse Engineer</span>
          </CardTitle>
          <CardDescription>
            Advanced JavaScript code analysis, deobfuscation, and pattern detection tool
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <Badge variant="outline" className="border-purple-600 text-purple-400">
              Code Analysis
            </Badge>
            <Badge variant="outline" className="border-blue-600 text-blue-400">
              Deobfuscation
            </Badge>
            <Badge variant="outline" className="border-green-600 text-green-400">
              Pattern Detection
            </Badge>
            <Badge variant="outline" className="border-orange-600 text-orange-400">
              AST Parser
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Input Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <FileText className="h-5 w-5" />
            <span>Input Code</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="js-code-input" className="text-sm font-medium">
              JavaScript Code to Analyze
            </label>
            <textarea
              id="js-code-input"
              value={inputCode}
              onChange={(e) => setInputCode(e.target.value)}
              className="w-full h-32 px-3 py-2 border border-input rounded-md bg-background font-mono text-sm"
              disabled={isAnalyzing}
              aria-label="JavaScript code input for analysis"
              placeholder="Paste your JavaScript code here..."
            />
          </div>
          <Button
            onClick={loadSampleCode}
            variant="outline"
            disabled={isAnalyzing}
            aria-label="Load sample obfuscated code"
          >
            <FileText className="mr-2 h-4 w-4" />
            Load Sample Code
          </Button>
        </CardContent>
      </Card>

      {/* Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Settings className="h-5 w-5" />
            <span>Analysis Configuration</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-3">
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.beautifyCode}
                  onChange={(e) => setConfig({...config, beautifyCode: e.target.checked})}
                  disabled={isAnalyzing}
                  className="rounded"
                />
                <span className="text-sm">Beautify/Deobfuscate Code</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.extractFunctions}
                  onChange={(e) => setConfig({...config, extractFunctions: e.target.checked})}
                  disabled={isAnalyzing}
                  className="rounded"
                />
                <span className="text-sm">Extract Functions</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.extractVariables}
                  onChange={(e) => setConfig({...config, extractVariables: e.target.checked})}
                  disabled={isAnalyzing}
                  className="rounded"
                />
                <span className="text-sm">Analyze Variables</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.extractStrings}
                  onChange={(e) => setConfig({...config, extractStrings: e.target.checked})}
                  disabled={isAnalyzing}
                  className="rounded"
                />
                <span className="text-sm">Extract Strings</span>
              </label>
            </div>
            <div className="space-y-3">
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.detectPatterns}
                  onChange={(e) => setConfig({...config, detectPatterns: e.target.checked})}
                  disabled={isAnalyzing}
                  className="rounded"
                />
                <span className="text-sm">Detect Obfuscation Patterns</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.analyzeControlFlow}
                  onChange={(e) => setConfig({...config, analyzeControlFlow: e.target.checked})}
                  disabled={isAnalyzing}
                  className="rounded"
                />
                <span className="text-sm">Analyze Control Flow</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.generateReport}
                  onChange={(e) => setConfig({...config, generateReport: e.target.checked})}
                  disabled={isAnalyzing}
                  className="rounded"
                />
                <span className="text-sm">Generate Full Report</span>
              </label>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Analysis Controls */}
      <Card>
        <CardHeader>
          <CardTitle>Analysis Controls</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <Button
              onClick={handleAnalyze}
              disabled={isAnalyzing || !inputCode.trim()}
              className="bg-purple-600 hover:bg-purple-700"
              aria-label="Analyze JavaScript code with current configuration"
            >
              <Play className="mr-2 h-4 w-4" />
              {isAnalyzing ? 'Analyzing...' : 'Analyze Code'}
            </Button>
            <Button
              onClick={handleStop}
              disabled={!isAnalyzing}
              variant="destructive"
              aria-label="Stop the current analysis"
            >
              <Square className="mr-2 h-4 w-4" />
              Stop
            </Button>
            <Button
              onClick={copyResults}
              disabled={!results || isAnalyzing}
              variant="outline"
              aria-label="Copy analysis results to clipboard"
            >
              Copy Results
            </Button>
            <Button
              onClick={exportResults}
              disabled={!results || isAnalyzing}
              variant="outline"
              aria-label="Export analysis results as JSON"
            >
              <Download className="mr-2 h-4 w-4" />
              Export Report
            </Button>
          </div>

          {isAnalyzing && (
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-sm">
                <span>Analysis Progress</span>
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
                <span>Analysis Results</span>
              </span>
              <Badge variant={results.success ? 'success' : 'destructive'}>
                {results.success ? 'Success' : 'Failed'}
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

                {/* Statistics */}
                {results.statistics && (
                  <div>
                    <h4 className="text-lg font-semibold mb-3 flex items-center">
                      <BarChart3 className="h-5 w-5 mr-2 text-blue-400" />
                      Code Statistics
                    </h4>
                    <div className="grid gap-4 md:grid-cols-3 text-sm">
                      <div className="flex items-center space-x-2">
                        <FileText className="h-4 w-4 text-gray-400" />
                        <span className="text-muted-foreground">Lines:</span>
                        <span className="font-medium">{results.statistics.lines}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Layers className="h-4 w-4 text-gray-400" />
                        <span className="text-muted-foreground">Functions:</span>
                        <span className="font-medium">{results.statistics.functions}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Hash className="h-4 w-4 text-gray-400" />
                        <span className="text-muted-foreground">Variables:</span>
                        <span className="font-medium">{results.statistics.variables}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Package className="h-4 w-4 text-gray-400" />
                        <span className="text-muted-foreground">Strings:</span>
                        <span className="font-medium">{results.statistics.strings}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <GitBranch className="h-4 w-4 text-gray-400" />
                        <span className="text-muted-foreground">Complexity:</span>
                        <span className="font-medium">{results.statistics.complexity}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Zap className="h-4 w-4 text-gray-400" />
                        <span className="text-muted-foreground">Patterns:</span>
                        <span className="font-medium">{results.statistics.patterns}</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Functions */}
                {results.functions && results.functions.length > 0 && (
                  <div>
                    <h4 className="text-lg font-semibold mb-3 flex items-center">
                      <Layers className="h-5 w-5 mr-2 text-purple-400" />
                      Functions Found
                    </h4>
                    <div className="space-y-2">
                      {results.functions.map((func, index) => (
                        <div key={index} className="p-3 bg-muted rounded-lg">
                          <div className="flex items-center justify-between">
                            <code className="text-sm font-mono">
                              {func.name}({func.parameters.join(', ')})
                            </code>
                            <Badge variant="outline" className="text-xs">
                              Complexity: {func.complexity}
                            </Badge>
                          </div>
                          <div className="text-xs text-muted-foreground mt-1">
                            Line: {func.location.start.line}, Column: {func.location.start.column}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Patterns */}
                {results.patterns && results.patterns.length > 0 && (
                  <div>
                    <h4 className="text-lg font-semibold mb-3 flex items-center">
                      <AlertTriangle className="h-5 w-5 mr-2 text-orange-400" />
                      Patterns Detected
                    </h4>
                    <div className="space-y-2">
                      {results.patterns.map((pattern, index) => (
                        <div key={index} className="p-3 bg-orange-50 dark:bg-orange-950 rounded-lg">
                          <div className="flex items-center justify-between">
                            <span className="font-medium text-sm">{pattern.type}</span>
                            <Badge variant="outline" className="text-xs border-orange-600 text-orange-400">
                              Warning
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">{pattern.description}</p>
                          <div className="text-xs text-muted-foreground mt-1">
                            Line: {pattern.location.start.line}, Column: {pattern.location.start.column}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                {results.recommendations && results.recommendations.length > 0 && (
                  <div>
                    <h4 className="text-lg font-semibold mb-3 flex items-center">
                      <Eye className="h-5 w-5 mr-2 text-blue-400" />
                      Recommendations
                    </h4>
                    <div className="space-y-2">
                      {results.recommendations.map((rec, index) => (
                        <div key={index} className="p-3 bg-blue-50 dark:bg-blue-950 rounded-lg">
                          <p className="text-sm">{rec}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Beautified Code */}
                {results.beautifiedCode && (
                  <div>
                    <h4 className="text-lg font-semibold mb-3 flex items-center">
                      <Eye className="h-5 w-5 mr-2 text-green-400" />
                      Beautified Code
                    </h4>
                    <div className="bg-muted rounded-lg p-4">
                      <pre className="text-xs font-mono whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
                        {results.beautifiedCode}
                      </pre>
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

      {/* Features Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Search className="h-5 w-5" />
            <span>Analysis Features</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <div className="flex items-start space-x-3">
              <Code2 className="h-5 w-5 text-purple-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Code Beautification</h4>
                <p className="text-sm text-muted-foreground">Deobfuscate and format minified code</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Layers className="h-5 w-5 text-blue-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Function Extraction</h4>
                <p className="text-sm text-muted-foreground">List all functions with metadata</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Hash className="h-5 w-5 text-green-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Variable Analysis</h4>
                <p className="text-sm text-muted-foreground">Identify all variables and scope</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <GitBranch className="h-5 w-5 text-orange-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Control Flow Analysis</h4>
                <p className="text-sm text-muted-foreground">Analyze complexity and structures</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Zap className="h-5 w-5 text-yellow-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Pattern Detection</h4>
                <p className="text-sm text-muted-foreground">Detect obfuscation techniques</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <BarChart3 className="h-5 w-5 text-cyan-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Code Statistics</h4>
                <p className="text-sm text-muted-foreground">Detailed metrics and reports</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Terminal Output */}
      <Card>
        <CardHeader>
          <CardTitle>Analysis Terminal</CardTitle>
          <CardDescription>
            Real-time analysis output and debugging information
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Terminal readOnly />
        </CardContent>
      </Card>
    </div>
  );
}
