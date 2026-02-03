"use client";

import { ProtectedRoute } from "@/components/auth/protected-route";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { useAuth } from "@/lib/auth-context";
import {
    Activity,
    AlertTriangle,
    BarChart3,
    Bug,
    CheckCircle,
    Code,
    Code2,
    Cpu,
    Eye,
    Globe,
    Key,
    Lock,
    LogOut,
    MessageSquare,
    Monitor,
    Network,
    Shield,
    ShieldCheck,
    Target,
    Terminal,
    Users,
    Zap
} from "lucide-react";
import { useState } from "react";

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const [isChatOpen, setIsChatOpen] = useState(false);

  const stats = [
    {
      title: "Active Tools",
      value: "9",
      change: "All operational",
      icon: Zap,
      color: "text-blue-400",
    },
    {
      title: "Security Agents",
      value: "5",
      change: "+2 this week",
      icon: Cpu,
      color: "text-green-400",
    },
    {
      title: "Security Score",
      value: "87%",
      change: "+5% improvement",
      icon: Shield,
      color: "text-purple-400",
    },
    {
      title: "Active Scans",
      value: "2",
      change: "Network + Code",
      icon: Activity,
      color: "text-yellow-400",
    },
  ];

  const recentActivities = [
    {
      id: 1,
      type: "exercise_completed",
      title: "Red Team Exercise Completed",
      description: "Network penetration testing exercise finished successfully",
      time: "2 hours ago",
      status: "success",
    },
    {
      id: 2,
      type: "vulnerability_found",
      title: "Critical Vulnerability Detected",
      description: "SQL injection vulnerability found in authentication module",
      time: "4 hours ago",
      status: "warning",
    },
    {
      id: 3,
      type: "team_member_added",
      title: "New Team Member Joined",
      description: "Alice Johnson added to Blue Team as Security Analyst",
      time: "6 hours ago",
      status: "info",
    },
    {
      id: 4,
      type: "exercise_started",
      title: "Purple Team Exercise Started",
      description: "Collaborative security exercise initiated",
      time: "8 hours ago",
      status: "info",
    },
  ];

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "success":
        return <CheckCircle className="h-4 w-4 text-green-400" />;
      case "warning":
        return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
      default:
        return <Activity className="h-4 w-4 text-blue-400" />;
    }
  };

  return (
    <ProtectedRoute requiredPermission="dashboard.view">
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        {/* Header */}
        <header className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-16">
              <div className="flex items-center">
                <div className="p-2 bg-gradient-to-br from-purple-600 to-blue-600 rounded-lg">
                  <Shield className="h-6 w-6 text-white" />
                </div>
                <div className="ml-4">
                  <h1 className="text-xl font-bold text-white">Security Orchestrator</h1>
                  <p className="text-sm text-gray-300">Enterprise Security Team Management</p>
                </div>
              </div>
              
              <div className="flex items-center space-x-4">
                <div className="text-right">
                  <p className="text-sm font-medium text-white">{user?.name}</p>
                  <p className="text-xs text-gray-300">{user?.role}</p>
                </div>
                <div className="relative">
                  <div className="h-8 w-8 rounded-full bg-gradient-to-br from-purple-600 to-blue-600 flex items-center justify-center">
                    <span className="text-sm font-bold text-white">
                      {user?.name?.charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <div className="absolute -bottom-1 -right-1 h-3 w-3 bg-green-400 rounded-full border-2 border-slate-800"></div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setIsChatOpen(true)}
                  className="text-gray-300 hover:text-white"
                  title="AI Chat Assistant"
                >
                  <MessageSquare className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={logout}
                  className="text-gray-300 hover:text-white"
                >
                  <LogOut className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </header>

        <OpenClawChat isOpen={isChatOpen} onClose={() => setIsChatOpen(false)} />

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Welcome Section */}
          <div className="mb-8">
            <h2 className="text-3xl font-bold text-white mb-2">
              Welcome back, {user?.name}
            </h2>
            <p className="text-gray-300">
              Here's what's happening with your security teams today.
            </p>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {stats.map((stat, index) => (
              <Card key={index} className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-gray-300">
                    {stat.title}
                  </CardTitle>
                  <stat.icon className={`h-4 w-4 ${stat.color}`} />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-white">{stat.value}</div>
                  <p className="text-xs text-gray-400">{stat.change}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Security Tools Section */}
          <div className="mb-8">
            <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
              <Zap className="h-6 w-6 mr-2 text-blue-400" />
              Active Security Tools
            </h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
              {/* Network Scanner Tool */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Network className="h-5 w-5 mr-2 text-blue-400" />
                    Network Scanner
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Scan networks and hosts for open ports, services, and vulnerabilities
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Last Scan</span>
                      <span className="text-xs text-gray-400">2 hours ago</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Targets Scanned</span>
                      <span className="text-sm font-medium">24 hosts</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Vulnerabilities Found</span>
                      <span className="text-sm font-medium text-yellow-400">7</span>
                    </div>
                    <Button className="w-full mt-4 bg-blue-600 hover:bg-blue-700">
                      Open Network Scanner
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Code Analysis Tool */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Code className="h-5 w-5 mr-2 text-green-400" />
                    Code Analysis
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Analyze code snippets for security vulnerabilities using static analysis and LLM
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Last Analysis</span>
                      <span className="text-xs text-gray-400">1 hour ago</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Files Analyzed</span>
                      <span className="text-sm font-medium">156 files</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Critical Issues</span>
                      <span className="text-sm font-medium text-red-400">3</span>
                    </div>
                    <Button className="w-full mt-4 bg-green-600 hover:bg-green-700">
                      Open Code Analysis
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Exploit Tools */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Bug className="h-5 w-5 mr-2 text-red-400" />
                    Exploit Tools
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Generate reverse shell payloads and adapt exploit templates using LLM
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Payloads Generated</span>
                      <span className="text-sm font-medium">42</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Templates Adapted</span>
                      <span className="text-sm font-medium">18</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Success Rate</span>
                      <span className="text-sm font-medium text-green-400">94%</span>
                    </div>
                    <Button className="w-full mt-4 bg-red-600 hover:bg-red-700">
                      Open Exploit Tools
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Password Cracker */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Key className="h-5 w-5 mr-2 text-yellow-400" />
                    Password Cracker
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Crack password hashes using Hashcat with various wordlists
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Hashes Cracked</span>
                      <span className="text-sm font-medium">127</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Algorithms</span>
                      <span className="text-sm font-medium">5 types</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Avg. Time</span>
                      <span className="text-sm font-medium">2.3 min</span>
                    </div>
                    <Button className="w-full mt-4 bg-yellow-600 hover:bg-yellow-700">
                      Open Password Cracker
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* AnyDesk Backdoor */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Monitor className="h-5 w-5 mr-2 text-purple-400" />
                    AnyDesk Backdoor
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Remote desktop backdoor tool for penetration testing and security assessment
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Deployments</span>
                      <span className="text-sm font-medium">12</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Active Sessions</span>
                      <span className="text-sm font-medium">3</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Success Rate</span>
                      <span className="text-sm font-medium text-green-400">98%</span>
                    </div>
                    <Button className="w-full mt-4 bg-purple-600 hover:bg-purple-700">
                      Open AnyDesk Backdoor
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* RustDesk */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Globe className="h-5 w-5 mr-2 text-orange-400" />
                    RustDesk Remote Desktop
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Open-source remote desktop solution with self-hosting capabilities
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Deployments</span>
                      <span className="text-sm font-medium">8</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Active Connections</span>
                      <span className="text-sm font-medium">5</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Server Type</span>
                      <span className="text-sm font-medium text-orange-400">Self-Hosted</span>
                    </div>
                    <Button className="w-full mt-4 bg-orange-600 hover:bg-orange-700">
                      Open RustDesk
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Reverse Engineer */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Code2 className="h-5 w-5 mr-2 text-purple-400" />
                    JavaScript Reverse Engineer
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Advanced code analysis, deobfuscation, and pattern detection
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Analyses</span>
                      <span className="text-sm font-medium">15</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Patterns Detected</span>
                      <span className="text-sm font-medium">23</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Avg Complexity</span>
                      <span className="text-sm font-medium text-purple-400">8.5</span>
                    </div>
                    <Button className="w-full mt-4 bg-purple-600 hover:bg-purple-700">
                      Open Reverse Engineer
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* BeEF Security Testing */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Shield className="h-5 w-5 mr-2 text-green-400" />
                    BeEF Security Testing
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Browser security testing for educational awareness training
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Test Sessions</span>
                      <span className="text-sm font-medium">12</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Browsers Hooked</span>
                      <span className="text-sm font-medium">8</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Security Issues</span>
                      <span className="text-sm font-medium text-green-400">Educational</span>
                    </div>
                    <Button className="w-full mt-4 bg-green-600 hover:bg-green-700">
                      Open BeEF Security
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Defensive Security Training */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <ShieldCheck className="h-5 w-5 mr-2 text-purple-400" />
                    Defensive Security Training
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Educational threat analysis and defensive strategy training
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-purple-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Training Modules</span>
                      <span className="text-sm font-medium">10</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Active Sessions</span>
                      <span className="text-sm font-medium">3</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Defensive Score</span>
                      <span className="text-sm font-medium text-purple-400">85%</span>
                    </div>
                    <Button className="w-full mt-4 bg-purple-600 hover:bg-purple-700">
                      Open Training
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Security Agents Section */}
          <div className="mb-8">
            <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
              <Cpu className="h-6 w-6 mr-2 text-purple-400" />
              Security Agents
            </h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
              {/* Red Team Agent */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Target className="h-5 w-5 mr-2 text-red-400" />
                    Red Team Agent
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Offensive security operations and penetration testing
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Current Exercise</span>
                      <span className="text-sm font-medium">Network Pentest</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Success Rate</span>
                      <span className="text-sm font-medium text-green-400">87%</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Last Activity</span>
                      <span className="text-xs text-gray-400">5 min ago</span>
                    </div>
                    <Button variant="outline" className="w-full border-red-600 text-red-400 hover:bg-red-900/20">
                      Configure Agent
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Blue Team Agent */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Shield className="h-5 w-5 mr-2 text-blue-400" />
                    Blue Team Agent
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Defensive security operations and threat detection
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Threats Blocked</span>
                      <span className="text-sm font-medium">234</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Response Time</span>
                      <span className="text-sm font-medium text-green-400">1.2 sec</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Last Alert</span>
                      <span className="text-xs text-gray-400">12 min ago</span>
                    </div>
                    <Button variant="outline" className="w-full border-blue-600 text-blue-400 hover:bg-blue-900/20">
                      Configure Agent
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Purple Team Agent */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Eye className="h-5 w-5 mr-2 text-purple-400" />
                    Purple Team Agent
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Collaborative security testing and validation
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="secondary" className="bg-yellow-600">
                        Standby
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Joint Exercises</span>
                      <span className="text-sm font-medium">18</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Effectiveness</span>
                      <span className="text-sm font-medium text-green-400">92%</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Last Exercise</span>
                      <span className="text-xs text-gray-400">2 hours ago</span>
                    </div>
                    <Button variant="outline" className="w-full border-purple-600 text-purple-400 hover:bg-purple-900/20">
                      Configure Agent
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Black Hat Agent */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Lock className="h-5 w-5 mr-2 text-gray-400" />
                    Black Hat Agent
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Advanced threat simulation and adversarial testing
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="outline" className="border-slate-600 text-gray-300">
                        Offline
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Simulations Run</span>
                      <span className="text-sm font-medium">67</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Threat Level</span>
                      <span className="text-sm font-medium text-red-400">High</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Last Run</span>
                      <span className="text-xs text-gray-400">1 day ago</span>
                    </div>
                    <Button variant="outline" className="w-full border-gray-600 text-gray-400 hover:bg-gray-900/20">
                      Activate Agent
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* LLM Agent */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Terminal className="h-5 w-5 mr-2 text-cyan-400" />
                    LLM Agent
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    AI-powered analysis and intelligent automation
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Queries Processed</span>
                      <span className="text-sm font-medium">1,247</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Accuracy</span>
                      <span className="text-sm font-medium text-green-400">96%</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Response Time</span>
                      <span className="text-xs text-gray-400">0.8 sec</span>
                    </div>
                    <Button variant="outline" className="w-full border-cyan-600 text-cyan-400 hover:bg-cyan-900/20">
                      Configure Agent
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Global Agent */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Globe className="h-5 w-5 mr-2 text-green-400" />
                    Global Agent
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Cross-platform security orchestration and management
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Status</span>
                      <Badge variant="default" className="bg-green-600">
                        Active
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Platforms Managed</span>
                      <span className="text-sm font-medium">12</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Global Score</span>
                      <span className="text-sm font-medium text-green-400">A+</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">Last Sync</span>
                      <span className="text-xs text-gray-400">Just now</span>
                    </div>
                    <Button variant="outline" className="w-full border-green-600 text-green-400 hover:bg-green-900/20">
                      Configure Agent
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* System Monitoring Section */}
          <div className="mb-8">
            <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
              <BarChart3 className="h-6 w-6 mr-2 text-blue-400" />
              System Monitoring
            </h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Resource Usage</CardTitle>
                  <CardDescription className="text-gray-300">
                    Real-time system resource consumption
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>CPU Usage</span>
                      <span className="text-blue-400">45%</span>
                    </div>
                    <Progress value={45} className="h-2" />
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Memory Usage</span>
                      <span className="text-green-400">62%</span>
                    </div>
                    <Progress value={62} className="h-2" />
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Disk Usage</span>
                      <span className="text-yellow-400">78%</span>
                    </div>
                    <Progress value={78} className="h-2" />
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Network I/O</span>
                      <span className="text-purple-400">23%</span>
                    </div>
                    <Progress value={23} className="h-2" />
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Service Health</CardTitle>
                  <CardDescription className="text-gray-300">
                    Overall system health and service status
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">API Gateway</span>
                    <Badge variant="default" className="bg-green-600">
                      Healthy
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">Database</span>
                    <Badge variant="default" className="bg-green-600">
                      Connected
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">LLM Service</span>
                    <Badge variant="default" className="bg-green-600">
                      Online
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">Agent Manager</span>
                    <Badge variant="default" className="bg-green-600">
                      Running
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">File Storage</span>
                    <Badge variant="default" className="bg-green-600">
                      Available
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">Last Backup</span>
                    <span className="text-xs text-gray-400">2 hours ago</span>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Main Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Recent Activities */}
            <div className="lg:col-span-2">
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Activity className="h-5 w-5 mr-2 text-blue-400" />
                    Recent Activities
                  </CardTitle>
                  <CardDescription className="text-gray-300">
                    Latest security team activities and events
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {recentActivities.map((activity) => (
                      <div
                        key={activity.id}
                        className="flex items-start space-x-3 p-3 rounded-lg bg-slate-700/30 hover:bg-slate-700/50 transition-colors"
                      >
                        <div className="mt-1">
                          {getStatusIcon(activity.status)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-white">
                            {activity.title}
                          </p>
                          <p className="text-sm text-gray-300">
                            {activity.description}
                          </p>
                          <p className="text-xs text-gray-400 mt-1">
                            {activity.time}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="mt-4">
                    <Button variant="outline" className="border-slate-600 text-gray-300 hover:bg-slate-700">
                      View All Activities
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Quick Actions */}
            <div className="space-y-6">
              {/* Quick Actions Card */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Target className="h-5 w-5 mr-2 text-purple-400" />
                    Quick Actions
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <Button className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700">
                    Start New Exercise
                  </Button>
                  <Button variant="outline" className="w-full border-slate-600 text-gray-300 hover:bg-slate-700">
                    Create Team
                  </Button>
                  <Button variant="outline" className="w-full border-slate-600 text-gray-300 hover:bg-slate-700">
                    Generate Report
                  </Button>
                  <Button variant="outline" className="w-full border-slate-600 text-gray-300 hover:bg-slate-700">
                    View Analytics
                  </Button>
                </CardContent>
              </Card>

              {/* Team Status */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Users className="h-5 w-5 mr-2 text-green-400" />
                    Team Status
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">Red Team</span>
                    <Badge variant="default" className="bg-green-600">
                      Active
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">Blue Team</span>
                    <Badge variant="default" className="bg-green-600">
                      Active
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">Purple Team</span>
                    <Badge variant="secondary" className="bg-yellow-600">
                      Standby
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">Black Hat</span>
                    <Badge variant="outline" className="border-slate-600 text-gray-300">
                      Offline
                    </Badge>
                  </div>
                </CardContent>
              </Card>

              {/* System Health */}
              <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <BarChart3 className="h-5 w-5 mr-2 text-blue-400" />
                    System Health
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">API Status</span>
                    <Badge variant="default" className="bg-green-600">
                      Healthy
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">Database</span>
                    <Badge variant="default" className="bg-green-600">
                      Connected
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">Services</span>
                    <Badge variant="default" className="bg-green-600">
                      Online
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-300">Last Backup</span>
                    <span className="text-xs text-gray-400">2 hours ago</span>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </main>
      </div>
    </ProtectedRoute>
  );
}
