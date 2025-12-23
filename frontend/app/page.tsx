'use client';

import { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Terminal } from '@/components/ui/terminal';
import { NetworkScan } from '@/components/network-scan';
import { CodeAnalysis } from '@/components/code-analysis';
import { ExploitTools } from '@/components/exploit-tools';
import { PasswordCracker } from '@/components/password-cracker';
import { Dashboard } from '@/components/dashboard';
import { 
  Shield, 
  Network, 
  Code, 
  Key, 
  Target, 
  Activity,
  AlertTriangle,
  CheckCircle,
  XCircle
} from 'lucide-react';

export default function Home() {
  const [activeTab, setActiveTab] = useState('dashboard');

  return (
    <div className="min-h-screen bg-security-dark">
      {/* Header */}
      <header className="border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center">
          <div className="flex items-center space-x-4">
            <Shield className="h-8 w-8 text-security-green" />
            <div>
              <h1 className="text-xl font-bold text-security-gradient">Alpha AI</h1>
              <p className="text-xs text-muted-foreground">Security Platform</p>
            </div>
          </div>
          <div className="ml-auto flex items-center space-x-4">
            <Badge variant="outline" className="text-security-green">
              <Activity className="mr-2 h-3 w-3" />
              Systems Online
            </Badge>
            <Badge variant="outline">
              API: localhost:8080
            </Badge>
            <Badge variant="outline">
              LLM: localhost:8000
            </Badge>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-6">
            <TabsTrigger value="dashboard" className="flex items-center space-x-2">
              <Activity className="h-4 w-4" />
              <span>Dashboard</span>
            </TabsTrigger>
            <TabsTrigger value="network" className="flex items-center space-x-2">
              <Network className="h-4 w-4" />
              <span>Network</span>
            </TabsTrigger>
            <TabsTrigger value="analysis" className="flex items-center space-x-2">
              <Code className="h-4 w-4" />
              <span>Analysis</span>
            </TabsTrigger>
            <TabsTrigger value="password" className="flex items-center space-x-2">
              <Key className="h-4 w-4" />
              <span>Password</span>
            </TabsTrigger>
            <TabsTrigger value="exploit" className="flex items-center space-x-2">
              <Target className="h-4 w-4" />
              <span>Exploit</span>
            </TabsTrigger>
            <TabsTrigger value="terminal" className="flex items-center space-x-2">
              <Terminal className="h-4 w-4" />
              <span>Terminal</span>
            </TabsTrigger>
          </TabsList>

          {/* Dashboard Tab */}
          <TabsContent value="dashboard" className="space-y-6">
            <Dashboard />
          </TabsContent>

          {/* Network Scan Tab */}
          <TabsContent value="network" className="space-y-6">
            <NetworkScan />
          </TabsContent>

          {/* Code Analysis Tab */}
          <TabsContent value="analysis" className="space-y-6">
            <CodeAnalysis />
          </TabsContent>

          {/* Password Cracker Tab */}
          <TabsContent value="password" className="space-y-6">
            <PasswordCracker />
          </TabsContent>

          {/* Exploit Tools Tab */}
          <TabsContent value="exploit" className="space-y-6">
            <ExploitTools />
          </TabsContent>

          {/* Terminal Tab */}
          <TabsContent value="terminal" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Terminal className="h-5 w-5" />
                  <span>Security Terminal</span>
                </CardTitle>
                <CardDescription>
                  Interactive terminal for running security commands and scripts
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Terminal />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-14 items-center justify-between">
          <p className="text-xs text-muted-foreground">
            © 2024 Alpha AI Security Platform. For authorized penetration testing only.
          </p>
          <div className="flex items-center space-x-4 text-xs text-muted-foreground">
            <span>Version 1.0.0</span>
            <span>•</span>
            <span>Next.js 14 + Tailwind CSS</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
