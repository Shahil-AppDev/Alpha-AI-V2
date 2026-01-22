'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Terminal } from '@/components/ui/terminal';
import {
    Activity,
    BookOpen,
    Camera,
    Crown,
    Database,
    Download,
    Eye,
    Globe,
    Info,
    Key,
    Lock,
    MapPin,
    Play,
    Shield,
    ShieldCheck,
    Smartphone,
    Square,
    Target,
    Users,
    Wifi
} from 'lucide-react';
import { useState } from 'react';

interface TrainingModule {
  id: string;
  name: string;
  category: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  duration: string;
  description: string;
  defensiveFocus: string;
  risks: string[];
  protections: string[];
  icon: any;
  color: string;
}

interface TrainingSession {
  moduleId: string;
  isActive: boolean;
  progress: number;
  startTime: Date;
  defensiveScore: number;
  understandingLevel: number;
}

const trainingModules: TrainingModule[] = [
  // RAT Analysis & Defense
  {
    id: 'rat-analysis',
    name: 'Remote Access Trojans (RATs)',
    category: 'Malware Analysis',
    difficulty: 'advanced',
    duration: '45 min',
    description: 'Educational analysis of RAT behavior, communication patterns, and defense strategies',
    defensiveFocus: 'Network monitoring, process analysis, C2 detection',
    risks: ['Unauthorized remote access', 'Data exfiltration', 'Persistence mechanisms'],
    protections: ['Network traffic analysis', 'Process monitoring', 'Firewall rules', 'Endpoint detection'],
    icon: Crown,
    color: 'text-red-600'
  },
  // Keylogger Defense
  {
    id: 'keylogger-defense',
    name: 'Keylogger Detection & Defense',
    category: 'Endpoint Security',
    difficulty: 'intermediate',
    duration: '30 min',
    description: 'Understanding keylogger techniques and implementing defensive measures',
    defensiveFocus: 'Input monitoring, process behavior analysis, anti-keylogger techniques',
    risks: ['Credential theft', 'Privacy invasion', 'Data leakage'],
    protections: ['Anti-keylogger software', 'Input validation', 'Process monitoring', 'Secure input methods'],
    icon: Key,
    color: 'text-orange-600'
  },
  // Data Exfiltration Defense
  {
    id: 'data-exfiltration',
    name: 'Data Exfiltration Prevention',
    category: 'Data Protection',
    difficulty: 'advanced',
    duration: '40 min',
    description: 'Identifying and preventing unauthorized data transfer techniques',
    defensiveFocus: 'DLP implementation, traffic analysis, data classification',
    risks: ['Intellectual property theft', 'Privacy breaches', 'Compliance violations'],
    protections: ['Data Loss Prevention', 'Network monitoring', 'Encryption', 'Access controls'],
    icon: Database,
    color: 'text-purple-600'
  },
  // Spyware Detection
  {
    id: 'spyware-detection',
    name: 'Spyware Detection & Removal',
    category: 'Malware Defense',
    difficulty: 'intermediate',
    duration: '35 min',
    description: 'Advanced spyware identification, analysis, and removal techniques',
    defensiveFocus: 'Behavioral analysis, system monitoring, forensic investigation',
    risks: ['Surveillance', 'Information gathering', 'Privacy violations'],
    protections: ['Anti-spyware tools', 'System monitoring', 'Privacy controls', 'Regular scanning'],
    icon: Eye,
    color: 'text-blue-600'
  },
  // Mobile Security
  {
    id: 'mobile-security',
    name: 'Mobile Device Security',
    category: 'Mobile Defense',
    difficulty: 'advanced',
    duration: '50 min',
    description: 'Mobile malware analysis and mobile security best practices',
    defensiveFocus: 'Mobile app security, MDM implementation, device hardening',
    risks: ['Mobile malware', 'Data leakage', 'Device compromise'],
    protections: ['Mobile security suites', 'MDM solutions', 'App vetting', 'Device encryption'],
    icon: Smartphone,
    color: 'text-green-600'
  },
  // Browser Security
  {
    id: 'browser-security',
    name: 'Browser-Based Threats',
    category: 'Web Security',
    difficulty: 'intermediate',
    duration: '30 min',
    description: 'Browser exploitation techniques and defense strategies',
    defensiveFocus: 'Browser hardening, script control, privacy protection',
    risks: ['Browser hijacking', 'Script injection', 'Privacy violations'],
    protections: ['Browser security settings', 'Script blocking', 'Privacy extensions', 'Regular updates'],
    icon: Globe,
    color: 'text-cyan-600'
  },
  // Network Surveillance Defense
  {
    id: 'network-defense',
    name: 'Network Surveillance Defense',
    category: 'Network Security',
    difficulty: 'advanced',
    duration: '45 min',
    description: 'Defending against network-based surveillance and monitoring',
    defensiveFocus: 'Traffic encryption, network monitoring, anomaly detection',
    risks: ['Traffic analysis', 'Network monitoring', 'Communication interception'],
    protections: ['Encryption', 'VPN/Tor usage', 'Network monitoring', 'Traffic analysis'],
    icon: Wifi,
    color: 'text-indigo-600'
  },
  // Audio/Video Security
  {
    id: 'av-security',
    name: 'Audio/Video Security',
    category: 'Hardware Security',
    difficulty: 'intermediate',
    duration: '25 min',
    description: 'Protecting against unauthorized audio and video surveillance',
    defensiveFocus: 'Hardware monitoring, device control, privacy protection',
    risks: ['Eavesdropping', 'Unauthorized recording', 'Privacy invasion'],
    protections: ['Hardware monitoring', 'Device control', 'Physical security', 'Privacy indicators'],
    icon: Camera,
    color: 'text-pink-600'
  },
  // Location Privacy
  {
    id: 'location-privacy',
    name: 'Location Privacy Protection',
    category: 'Privacy Security',
    difficulty: 'beginner',
    duration: '20 min',
    description: 'Protecting location data and preventing tracking',
    defensiveFocus: 'GPS security, location services control, privacy settings',
    risks: ['Location tracking', 'Movement profiling', 'Privacy invasion'],
    protections: ['Location services control', 'GPS spoofing', 'Privacy settings', 'Secure communications'],
    icon: MapPin,
    color: 'text-yellow-600'
  },
  // Detection & Analysis
  {
    id: 'threat-detection',
    name: 'Advanced Threat Detection',
    category: 'Security Operations',
    difficulty: 'advanced',
    duration: '60 min',
    description: 'Comprehensive threat detection and analysis techniques',
    defensiveFocus: 'SIEM operations, threat hunting, incident response',
    risks: ['Advanced persistent threats', 'Zero-day attacks', 'Sophisticated malware'],
    protections: ['SIEM solutions', 'Threat intelligence', 'Behavioral analysis', 'Incident response'],
    icon: ShieldCheck,
    color: 'text-emerald-600'
  }
];

export function DefensiveSecurityTraining() {
  const [selectedModule, setSelectedModule] = useState<TrainingModule | null>(null);
  const [activeSessions, setActiveSessions] = useState<TrainingSession[]>([]);
  const [currentView, setCurrentView] = useState<'overview' | 'training' | 'analysis'>('overview');
  const [defensiveScore, setDefensiveScore] = useState(0);

  const startTraining = (module: TrainingModule) => {
    const session: TrainingSession = {
      moduleId: module.id,
      isActive: true,
      progress: 0,
      startTime: new Date(),
      defensiveScore: 0,
      understandingLevel: 0
    };
    
    setActiveSessions([...activeSessions, session]);
    setSelectedModule(module);
    setCurrentView('training');
    
    // Simulate training progress
    simulateTrainingProgress(session);
  };

  const simulateTrainingProgress = (session: TrainingSession) => {
    const interval = setInterval(() => {
      setActiveSessions(prev => {
        const updated = prev.map(s => {
          if (s.moduleId === session.moduleId && s.isActive) {
            const newProgress = Math.min(s.progress + 10, 100);
            const newScore = Math.min(s.defensiveScore + 5, 100);
            const newUnderstanding = Math.min(s.understandingLevel + 8, 100);
            
            if (newProgress >= 100) {
              clearInterval(interval);
              return { ...s, progress: 100, isActive: false, defensiveScore: newScore, understandingLevel: newUnderstanding };
            }
            
            return { ...s, progress: newProgress, defensiveScore: newScore, understandingLevel: newUnderstanding };
          }
          return s;
        });
        return updated;
      });
    }, 2000);
  };

  const stopTraining = (moduleId: string) => {
    setActiveSessions(prev => 
      prev.map(s => s.moduleId === moduleId ? { ...s, isActive: false } : s)
    );
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'bg-green-600';
      case 'intermediate': return 'bg-yellow-600';
      case 'advanced': return 'bg-red-600';
      default: return 'bg-gray-600';
    }
  };

  const getActiveSession = (moduleId: string) => {
    return activeSessions.find(s => s.moduleId === moduleId);
  };

  const overallDefensiveScore = activeSessions.length > 0 
    ? Math.round(activeSessions.reduce((acc, s) => acc + s.defensiveScore, 0) / activeSessions.length)
    : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <ShieldCheck className="h-5 w-5 text-green-400" />
            <span>Defensive Security Training</span>
          </CardTitle>
          <CardDescription>
            Educational analysis of high-risk threats for defensive security training
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-4">
            <Badge variant="outline" className="border-green-600 text-green-400">
              Educational Purpose
            </Badge>
            <Badge variant="outline" className="border-blue-600 text-blue-400">
              Defense Focus
            </Badge>
            <Badge variant="outline" className="border-purple-600 text-purple-400">
              Security Awareness
            </Badge>
            <Badge variant="outline" className="border-orange-600 text-orange-400">
              Threat Analysis
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Educational Notice */}
      <Card className="border-blue-600 bg-blue-50/10">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2 text-blue-400">
            <Info className="h-5 w-5" />
            <span>Educational Security Training</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            <p className="text-blue-200">
              <strong>Defensive Security Education Only</strong>
            </p>
            <ul className="list-disc list-inside text-blue-300 space-y-1">
              <li>Analyze threats to understand defensive strategies</li>
              <li>Learn detection and prevention techniques</li>
              <li>Develop incident response capabilities</li>
              <li>Enhance security awareness and preparedness</li>
              <li>All training conducted in isolated, controlled environments</li>
            </ul>
          </div>
        </CardContent>
      </Card>

      {/* Overall Progress */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="flex items-center space-x-2">
              <Target className="h-5 w-5 text-purple-400" />
              Training Progress
            </span>
            <Badge variant="outline" className="text-lg px-3 py-1">
              Score: {overallDefensiveScore}%
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex justify-between text-sm">
              <span>Overall Defensive Readiness</span>
              <span>{overallDefensiveScore}%</span>
            </div>
            <Progress value={overallDefensiveScore} className="h-3" />
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-400">{activeSessions.length}</div>
                <div className="text-gray-400">Active Sessions</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-400">
                  {activeSessions.filter(s => s.progress >= 100).length}
                </div>
                <div className="text-gray-400">Completed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-400">
                  {activeSessions.filter(s => s.isActive).length}
                </div>
                <div className="text-gray-400">In Progress</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-400">
                  {trainingModules.filter(m => !activeSessions.some(s => s.moduleId === m.id)).length}
                </div>
                <div className="text-gray-400">Available</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Training Modules */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {trainingModules.map((module) => {
          const session = getActiveSession(module.id);
          const isActive = session?.isActive || false;
          const progress = session?.progress || 0;
          const defensiveScore = session?.defensiveScore || 0;
          
          return (
            <Card key={module.id} className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span className="flex items-center space-x-2">
                    <module.icon className={`h-5 w-5 ${module.color}`} />
                    <span className="text-white">{module.name}</span>
                  </span>
                  <Badge variant="outline" className={getDifficultyColor(module.difficulty)}>
                    {module.difficulty}
                  </Badge>
                </CardTitle>
                <CardDescription className="text-gray-300">
                  {module.description}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {/* Module Info */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">Category</span>
                      <span className="text-white">{module.category}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">Duration</span>
                      <span className="text-white">{module.duration}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">Defensive Focus</span>
                      <span className="text-green-400">{module.defensiveFocus}</span>
                    </div>
                  </div>

                  {/* Progress */}
                  {progress > 0 && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>Training Progress</span>
                        <span>{progress}%</span>
                      </div>
                      <Progress value={progress} className="h-2" />
                      <div className="flex justify-between text-sm">
                        <span>Defensive Score</span>
                        <span className="text-green-400">{defensiveScore}%</span>
                      </div>
                    </div>
                  )}

                  {/* Risks & Protections */}
                  <div className="space-y-2">
                    <div className="text-sm font-medium text-red-400">Threats Analyzed:</div>
                    <div className="flex flex-wrap gap-1">
                      {module.risks.slice(0, 3).map((risk, index) => (
                        <Badge key={index} variant="outline" className="text-xs border-red-600 text-red-400">
                          {risk}
                        </Badge>
                      ))}
                    </div>
                    <div className="text-sm font-medium text-green-400">Defensive Skills:</div>
                    <div className="flex flex-wrap gap-1">
                      {module.protections.slice(0, 3).map((protection, index) => (
                        <Badge key={index} variant="outline" className="text-xs border-green-600 text-green-400">
                          {protection}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex space-x-2">
                    {!isActive ? (
                      <Button
                        onClick={() => startTraining(module)}
                        className="flex-1 bg-green-600 hover:bg-green-700"
                        disabled={progress >= 100}
                      >
                        <Play className="mr-2 h-4 w-4" />
                        {progress >= 100 ? 'Completed' : 'Start Training'}
                      </Button>
                    ) : (
                      <Button
                        onClick={() => stopTraining(module.id)}
                        variant="destructive"
                        className="flex-1"
                      >
                        <Square className="mr-2 h-4 w-4" />
                        Stop Training
                      </Button>
                    )}
                    {progress >= 100 && (
                      <Button variant="outline" size="sm">
                        <Download className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Training Terminal */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Terminal className="h-5 w-5 text-blue-400" />
            <span>Security Analysis Terminal</span>
          </CardTitle>
          <CardDescription>
            Real-time defensive security training output and analysis
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Terminal readOnly />
        </CardContent>
      </Card>

      {/* Educational Resources */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <BookOpen className="h-5 w-5 text-purple-400" />
            <span>Defensive Security Resources</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <div className="flex items-start space-x-3">
              <Shield className="h-5 w-5 text-green-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Threat Intelligence</h4>
                <p className="text-sm text-muted-foreground">Latest threat analysis and defensive strategies</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Eye className="h-5 w-5 text-blue-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Detection Techniques</h4>
                <p className="text-sm text-muted-foreground">Advanced detection and analysis methods</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Lock className="h-5 w-5 text-orange-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Protection Strategies</h4>
                <p className="text-sm text-muted-foreground">Comprehensive protection implementation</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Activity className="h-5 w-5 text-purple-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Incident Response</h4>
                <p className="text-sm text-muted-foreground">Effective response and recovery procedures</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Users className="h-5 w-5 text-cyan-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Security Awareness</h4>
                <p className="text-sm text-muted-foreground">User education and training programs</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Target className="h-5 w-5 text-red-400 mt-0.5" />
              <div>
                <h4 className="font-medium">Risk Assessment</h4>
                <p className="text-sm text-muted-foreground">Comprehensive risk evaluation and mitigation</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
