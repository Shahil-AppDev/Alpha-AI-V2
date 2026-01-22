"use client";

import { ProtectedRoute } from "@/components/auth/protected-route";
import { BeefSecurity } from "@/components/beef-security";

export default function BeefSecurityPage() {
  return (
    <ProtectedRoute requiredPermission="tools.beef-security">
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-green-900 to-slate-900">
        {/* Header */}
        <header className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center h-16">
              <div className="flex items-center">
                <div className="p-2 bg-gradient-to-br from-green-600 to-blue-600 rounded-lg">
                  <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <div className="ml-4">
                  <h1 className="text-xl font-bold text-white">BeEF Security Testing</h1>
                  <p className="text-sm text-gray-300">Educational Browser Security Framework</p>
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <BeefSecurity />
        </main>
      </div>
    </ProtectedRoute>
  );
}
