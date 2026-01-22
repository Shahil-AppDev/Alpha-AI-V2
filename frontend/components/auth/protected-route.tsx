"use client";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/lib/auth-context";
import { Lock } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredPermission?: string;
  fallback?: React.ReactNode;
}

export function ProtectedRoute({ 
  children, 
  requiredPermission, 
  fallback 
}: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, hasPermission, user } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push("/auth");
    }
  }, [isAuthenticated, isLoading, router]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600 mx-auto mb-4"></div>
          <p className="text-gray-300">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return fallback || null;
  }

  if (requiredPermission && !hasPermission(requiredPermission)) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-4">
        <Card className="w-full max-w-md bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 p-3 bg-red-500/20 rounded-full">
              <Lock className="h-8 w-8 text-red-400" />
            </div>
            <CardTitle className="text-white">Access Denied</CardTitle>
            <CardDescription className="text-gray-300">
              You don't have permission to access this resource
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="bg-slate-700/30 p-4 rounded-lg">
              <div className="text-sm text-gray-300">
                <p className="font-medium text-red-400 mb-1">Required Permission:</p>
                <p className="font-mono">{requiredPermission}</p>
              </div>
            </div>
            <div className="bg-slate-700/30 p-4 rounded-lg">
              <div className="text-sm text-gray-300">
                <p className="font-medium text-blue-400 mb-1">Your Role:</p>
                <p className="font-mono">{user?.role || "Unknown"}</p>
                <p className="font-medium text-blue-400 mb-1 mt-2">Your Permissions:</p>
                <div className="font-mono text-xs">
                  {user?.permissions.length ? (
                    user.permissions.map((perm, index) => (
                      <span key={index} className="block">
                        {perm}
                      </span>
                    ))
                  ) : (
                    <span>No permissions assigned</span>
                  )}
                </div>
              </div>
            </div>
            <Button 
              onClick={() => router.back()} 
              variant="outline" 
              className="w-full border-slate-600 text-gray-300 hover:bg-slate-700"
            >
              Go Back
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return <>{children}</>;
}
