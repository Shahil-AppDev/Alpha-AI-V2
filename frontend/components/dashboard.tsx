'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { 
  Activity, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  TrendingUp,
  TrendingDown,
  Target,
  Network,
  Code,
  Key
} from 'lucide-react';

interface DashboardStats {
  totalScans: number;
  vulnerabilitiesFound: number;
  exploitsGenerated: number;
  passwordsCracked: number;
  systemHealth: number;
  activeConnections: number;
}

interface RecentActivity {
  id: string;
  type: 'scan' | 'analysis' | 'exploit' | 'password';
  description: string;
  timestamp: Date;
  status: 'success' | 'warning' | 'error';
}

export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>({
    totalScans: 0,
    vulnerabilitiesFound: 0,
    exploitsGenerated: 0,
    passwordsCracked: 0,
    systemHealth: 100,
    activeConnections: 0,
  });

  const [recentActivity, setRecentActivity] = useState<RecentActivity[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Simulate loading dashboard data
    const loadDashboardData = async () => {
      setIsLoading(true);
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setStats({
        totalScans: 47,
        vulnerabilitiesFound: 23,
        exploitsGenerated: 12,
        passwordsCracked: 8,
        systemHealth: 94,
        activeConnections: 3,
      });

      setRecentActivity([
        {
          id: '1',
          type: 'scan',
          description: 'Network scan completed for 192.168.1.0/24',
          timestamp: new Date(Date.now() - 5 * 60 * 1000),
          status: 'success'
        },
        {
          id: '2',
          type: 'analysis',
          description: 'Code analysis found 3 vulnerabilities',
          timestamp: new Date(Date.now() - 15 * 60 * 1000),
          status: 'warning'
        },
        {
          id: '3',
          type: 'exploit',
          description: 'Reverse shell payload generated successfully',
          timestamp: new Date(Date.now() - 30 * 60 * 1000),
          status: 'success'
        },
        {
          id: '4',
          type: 'password',
          description: 'Hashcat failed to crack password hash',
          timestamp: new Date(Date.now() - 45 * 60 * 1000),
          status: 'error'
        },
      ]);
      
      setIsLoading(false);
    };

    loadDashboardData();
  }, []);

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'scan': return <Network className="h-4 w-4" />;
      case 'analysis': return <Code className="h-4 w-4" />;
      case 'exploit': return <Target className="h-4 w-4" />;
      case 'password': return <Key className="h-4 w-4" />;
      default: return <Activity className="h-4 w-4" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'success': return <Badge variant="success" className="text-xs">Success</Badge>;
      case 'warning': return <Badge variant="warning" className="text-xs">Warning</Badge>;
      case 'error': return <Badge variant="destructive" className="text-xs">Error</Badge>;
      default: return <Badge variant="secondary" className="text-xs">Unknown</Badge>;
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i} className="animate-pulse">
              <CardHeader className="pb-2">
                <div className="h-4 w-20 bg-muted rounded"></div>
              </CardHeader>
              <CardContent>
                <div className="h-8 w-16 bg-muted rounded"></div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Network className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalScans}</div>
            <p className="text-xs text-muted-foreground">
              <TrendingUp className="inline h-3 w-3 mr-1" />
              +12% from last week
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.vulnerabilitiesFound}</div>
            <p className="text-xs text-muted-foreground">
              <TrendingDown className="inline h-3 w-3 mr-1" />
              -5% from last week
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Exploits Generated</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.exploitsGenerated}</div>
            <p className="text-xs text-muted-foreground">
              <TrendingUp className="inline h-3 w-3 mr-1" />
              +8% from last week
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Passwords Cracked</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.passwordsCracked}</div>
            <p className="text-xs text-muted-foreground">
              <TrendingUp className="inline h-3 w-3 mr-1" />
              +3 from last week
            </p>
          </CardContent>
        </Card>
      </div>

      {/* System Status and Activity */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* System Status */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Shield className="h-5 w-5" />
              <span>System Status</span>
            </CardTitle>
            <CardDescription>
              Overall system health and service status
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>System Health</span>
                <span className="text-security-green">{stats.systemHealth}%</span>
              </div>
              <Progress value={stats.systemHealth} className="h-2" />
            </div>

            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Active Connections</span>
                <span>{stats.activeConnections}</span>
              </div>
              <Progress value={(stats.activeConnections / 10) * 100} className="h-2" />
            </div>

            <div className="grid grid-cols-2 gap-4 pt-2">
              <div className="flex items-center space-x-2">
                <CheckCircle className="h-4 w-4 text-security-green" />
                <span className="text-sm">Agent App</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="h-4 w-4 text-security-green" />
                <span className="text-sm">LLM Service</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="h-4 w-4 text-security-green" />
                <span className="text-sm">Database</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="h-4 w-4 text-security-green" />
                <span className="text-sm">File Storage</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Activity className="h-5 w-5" />
              <span>Recent Activity</span>
            </CardTitle>
            <CardDescription>
              Latest security operations and results
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentActivity.map((activity) => (
                <div key={activity.id} className="flex items-center space-x-3">
                  <div className="flex-shrink-0">
                    {getActivityIcon(activity.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
                      {activity.description}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {activity.timestamp.toLocaleTimeString()}
                    </p>
                  </div>
                  <div className="flex-shrink-0">
                    {getStatusBadge(activity.status)}
                  </div>
                </div>
              ))}
            </div>
            
            <div className="mt-4 pt-4 border-t">
              <Button variant="outline" size="sm" className="w-full">
                View All Activity
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>
            Common security tasks and operations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Button variant="outline" className="h-20 flex-col space-y-2">
              <Network className="h-6 w-6" />
              <span>Network Scan</span>
            </Button>
            <Button variant="outline" className="h-20 flex-col space-y-2">
              <Code className="h-6 w-6" />
              <span>Code Analysis</span>
            </Button>
            <Button variant="outline" className="h-20 flex-col space-y-2">
              <Target className="h-6 w-6" />
              <span>Generate Exploit</span>
            </Button>
            <Button variant="outline" className="h-20 flex-col space-y-2">
              <Key className="h-6 w-6" />
              <span>Crack Password</span>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
