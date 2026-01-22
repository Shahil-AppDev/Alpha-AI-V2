'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';

export default function AdminDashboard() {
  const [user, setUser] = useState<any>(null);
  const router = useRouter();

  useEffect(() => {
    // Check if user is authenticated
    const token = localStorage.getItem('adminToken');
    const userData = localStorage.getItem('adminUser');

    if (!token || !userData) {
      router.push('/admin/login');
      return;
    }

    setUser(JSON.parse(userData));
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem('adminToken');
    localStorage.removeItem('adminUser');
    router.push('/admin/login');
  };

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-white">Chargement...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-black">
      <nav className="bg-gray-800/50 backdrop-blur-lg border-b border-purple-500/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-white">Alpha AI - Admin Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-300">Bienvenue, {user.username}</span>
              <button
                onClick={handleLogout}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
              >
                Déconnexion
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Security Tools Card */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl p-6 border border-purple-500/20">
            <h2 className="text-xl font-bold text-white mb-4">🔐 Outils de Sécurité</h2>
            <p className="text-gray-400 mb-4">Accès aux outils de cybersécurité</p>
            <a
              href="/tools"
              className="inline-block px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
            >
              Accéder
            </a>
          </div>

          {/* Dashboard Stats */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl p-6 border border-purple-500/20">
            <h2 className="text-xl font-bold text-white mb-4">📊 Statistiques</h2>
            <p className="text-gray-400 mb-4">Vue d'ensemble du système</p>
            <a
              href="/dashboard"
              className="inline-block px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
            >
              Voir Stats
            </a>
          </div>

          {/* AI Features */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl p-6 border border-purple-500/20">
            <h2 className="text-xl font-bold text-white mb-4">🤖 IA & Agents</h2>
            <p className="text-gray-400 mb-4">Gestion des agents IA</p>
            <a
              href="/ai"
              className="inline-block px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
            >
              Gérer
            </a>
          </div>

          {/* Server Management */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl p-6 border border-purple-500/20">
            <h2 className="text-xl font-bold text-white mb-4">🖥️ Serveur</h2>
            <p className="text-gray-400 mb-4">Gestion du serveur</p>
            <div className="space-y-2">
              <p className="text-sm text-gray-300">IP: 157.180.107.154</p>
              <p className="text-sm text-green-400">● En ligne</p>
            </div>
          </div>

          {/* Deployment */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl p-6 border border-purple-500/20">
            <h2 className="text-xl font-bold text-white mb-4">🚀 Déploiement</h2>
            <p className="text-gray-400 mb-4">Gestion des déploiements</p>
            <a
              href="https://github.com/Shahil-AppDev/Alpha-AI-V2/actions"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-block px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
            >
              GitHub Actions
            </a>
          </div>

          {/* Settings */}
          <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl p-6 border border-purple-500/20">
            <h2 className="text-xl font-bold text-white mb-4">⚙️ Paramètres</h2>
            <p className="text-gray-400 mb-4">Configuration système</p>
            <button className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors">
              Configurer
            </button>
          </div>
        </div>

        {/* System Info */}
        <div className="mt-8 bg-gray-800/50 backdrop-blur-lg rounded-xl p-6 border border-purple-500/20">
          <h2 className="text-xl font-bold text-white mb-4">ℹ️ Informations Système</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-gray-300">
            <div>
              <p className="text-sm text-gray-400">Utilisateur</p>
              <p className="font-mono">{user.username}</p>
            </div>
            <div>
              <p className="text-sm text-gray-400">Email</p>
              <p className="font-mono">{user.email}</p>
            </div>
            <div>
              <p className="text-sm text-gray-400">Rôle</p>
              <p className="font-mono uppercase">{user.role}</p>
            </div>
            <div>
              <p className="text-sm text-gray-400">Version</p>
              <p className="font-mono">Alpha AI v2.0</p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
