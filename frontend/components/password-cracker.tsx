'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Terminal } from '@/components/ui/terminal';
import { 
  Key, 
  Play, 
  Square, 
  Upload,
  Download,
  CheckCircle,
  XCircle,
  AlertTriangle
} from 'lucide-react';

interface CrackResult {
  hash: string;
  cracked: boolean;
  password?: string;
  algorithm: string;
  time_taken: number;
}

export function PasswordCracker() {
  const [hashInput, setHashInput] = useState('');
  const [wordlistPath, setWordlistPath] = useState('/usr/share/wordlists/rockyou.txt');
  const [isCracking, setIsCracking] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<CrackResult[]>([]);
  const [algorithm, setAlgorithm] = useState('md5');

  const sampleHashes = {
    md5: '5f4dcc3b5aa765d61d8327deb882cf99', // "password"
    sha1: '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', // "password"
    sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' // "password"
  };

  const handleCrack = async () => {
    if (!hashInput.trim()) return;

    setIsCracking(true);
    setProgress(0);

    try {
      // Simulate cracking progress
      for (let i = 0; i <= 100; i += 5) {
        setProgress(i);
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      // Mock result
      const result: CrackResult = {
        hash: hashInput,
        cracked: Math.random() > 0.3, // 70% success rate for demo
        password: Math.random() > 0.3 ? 'password' : undefined,
        algorithm: algorithm,
        time_taken: Math.floor(Math.random() * 300) + 60
      };

      setResults([result]);
    } catch (error) {
      console.error('Cracking failed:', error);
    } finally {
      setIsCracking(false);
      setProgress(0);
    }
  };

  const handleStop = () => {
    setIsCracking(false);
    setProgress(0);
  };

  const loadSampleHash = () => {
    setHashInput(sampleHashes[algorithm as keyof typeof sampleHashes]);
  };

  const clearResults = () => {
    setResults([]);
    setHashInput('');
  };

  const exportResults = () => {
    if (results.length === 0) return;
    
    const data = JSON.stringify(results, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `password-crack-results-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Key className="h-5 w-5" />
            <span>Password Cracker</span>
          </CardTitle>
          <CardDescription>
            Crack password hashes using Hashcat with various wordlists
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <label className="text-sm font-medium">Hash Algorithm</label>
              <select
                value={algorithm}
                onChange={(e) => setAlgorithm(e.target.value)}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isCracking}
              >
                <option value="md5">MD5</option>
                <option value="sha1">SHA1</option>
                <option value="sha256">SHA256</option>
                <option value="ntlm">NTLM</option>
                <option value="bcrypt">bcrypt</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Wordlist Path</label>
              <input
                type="text"
                value={wordlistPath}
                onChange={(e) => setWordlistPath(e.target.value)}
                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                disabled={isCracking}
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Hash to Crack</label>
            <textarea
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
              placeholder="Enter hash(es) to crack, one per line..."
              className="w-full h-32 px-3 py-2 border border-input rounded-md bg-background font-mono text-sm"
              disabled={isCracking}
            />
          </div>

          <div className="flex items-center space-x-2">
            <Button
              onClick={handleCrack}
              disabled={isCracking || !hashInput.trim()}
              className="security-button"
            >
              <Play className="mr-2 h-4 w-4" />
              {isCracking ? 'Cracking...' : 'Start Cracking'}
            </Button>
            <Button
              onClick={handleStop}
              disabled={!isCracking}
              variant="destructive"
            >
              <Square className="mr-2 h-4 w-4" />
              Stop
            </Button>
            <Button
              onClick={loadSampleHash}
              disabled={isCracking}
              variant="outline"
            >
              Load Sample Hash
            </Button>
            <Button
              onClick={clearResults}
              disabled={isCracking}
              variant="outline"
            >
              Clear
            </Button>
          </div>

          {isCracking && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Cracking Progress</span>
                <span>{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
        </CardContent>
      </Card>

      {/* Results */}
      {results.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Cracking Results</span>
              <Button
                onClick={exportResults}
                variant="outline"
                size="sm"
              >
                <Download className="mr-2 h-4 w-4" />
                Export
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {results.map((result, index) => (
                <div key={index} className="border rounded-lg p-4">
                  <div className="flex items-start justify-between">
                    <div className="space-y-2">
                      <div className="flex items-center space-x-2">
                        {result.cracked ? (
                          <CheckCircle className="h-5 w-5 text-security-green" />
                        ) : (
                          <XCircle className="h-5 w-5 text-security-red" />
                        )}
                        <span className="font-medium">
                          {result.cracked ? 'Successfully Cracked' : 'Crack Failed'}
                        </span>
                      </div>
                      
                      <div className="grid gap-2 text-sm">
                        <div>
                          <span className="text-muted-foreground">Hash: </span>
                          <code className="bg-muted px-1 rounded">{result.hash}</code>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Algorithm: </span>
                          <span>{result.algorithm.toUpperCase()}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Time: </span>
                          <span>{result.time_taken}s</span>
                        </div>
                        {result.password && (
                          <div>
                            <span className="text-muted-foreground">Password: </span>
                            <code className="bg-security-green text-white px-2 py-1 rounded">
                              {result.password}
                            </code>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <Badge variant={result.cracked ? 'success' : 'destructive'}>
                      {result.cracked ? 'Success' : 'Failed'}
                    </Badge>
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
          <CardTitle>Hashcat Terminal</CardTitle>
          <CardDescription>
            Real-time cracking progress and Hashcat output
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Terminal readOnly />
        </CardContent>
      </Card>
    </div>
  );
}
