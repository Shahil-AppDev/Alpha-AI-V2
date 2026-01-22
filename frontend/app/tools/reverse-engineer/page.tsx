"use client";

import { ProtectedRoute } from "@/components/auth/protected-route";
import { ReverseEngineer } from "@/components/reverse-engineer";

export default function ReverseEngineerPage() {
  return (
    <ProtectedRoute requiredPermission="tools.reverse-engineer">
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        {/* Header */}
        <header className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center h-16">
              <div className="flex items-center">
                <div className="p-2 bg-gradient-to-br from-purple-600 to-pink-600 rounded-lg">
                  <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                  </svg>
                </div>
                <div className="ml-4">
                  <h1 className="text-xl font-bold text-white">JavaScript Reverse Engineer</h1>
                  <p className="text-sm text-gray-300">Advanced Code Analysis & Deobfuscation</p>
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <ReverseEngineer />
        </main>
      </div>
    </ProtectedRoute>
  );
}
