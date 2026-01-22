"use client";

import { AnyDeskBackdoor } from "@/components/anydesk-backdoor";
import { ProtectedRoute } from "@/components/auth/protected-route";

export default function AnyDeskBackdoorPage() {
  return (
    <ProtectedRoute requiredPermission="tools.anydesk">
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        {/* Header */}
        <header className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center h-16">
              <div className="flex items-center">
                <div className="p-2 bg-gradient-to-br from-purple-600 to-blue-600 rounded-lg">
                  <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                </div>
                <div className="ml-4">
                  <h1 className="text-xl font-bold text-white">AnyDesk Backdoor</h1>
                  <p className="text-sm text-gray-300">Remote Desktop Access Tool</p>
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <AnyDeskBackdoor />
        </main>
      </div>
    </ProtectedRoute>
  );
}
