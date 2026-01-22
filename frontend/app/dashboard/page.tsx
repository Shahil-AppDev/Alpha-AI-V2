"use client";

import { ProtectedRoute } from "@/components/auth/protected-route";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/lib/auth-context";
import {
    Activity,
    AlertTriangle,
    BarChart3,
    CheckCircle,
    Clock,
    LogOut,
    Shield,
    Target,
    Users
} from "lucide-react";

export default function DashboardPage() {
  const { user, logout } = useAuth();

  const stats = [
    {
      title: "Active Exercises",
      value: "3",
      change: "+1 from yesterday",
      icon: Activity,
      color: "text-blue-400",
    },
    {
      title: "Team Members",
      value: "24",
      change: "+2 this week",
      icon: Users,
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
      title: "Pending Tasks",
      value: "7",
      change: "-3 from yesterday",
      icon: Clock,
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
                  onClick={logout}
                  className="text-gray-300 hover:text-white"
                >
                  <LogOut className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </header>

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
