'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Cpu, Target, Shield, Eye, Lock, Terminal, Activity, Send, Loader2 } from 'lucide-react';

interface Agent {
  id: string;
  name: string;
  type: 'red-team' | 'blue-team' | 'purple-team' | 'black-hat' | 'llm-agent';
  status: 'active' | 'standby' | 'offline';
  model: string;
  description: string;
  capabilities: string[];
  stats: {
    tasksCompleted: number;
    successRate: number;
    lastActivity: Date;
  };
}

interface AgentsPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

export function AgentsPanel({ isOpen, onClose }: AgentsPanelProps) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [task, setTask] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<string>('');

  useEffect(() => {
    if (isOpen) {
      fetchAgents();
    }
  }, [isOpen]);

  const fetchAgents = async () => {
    try {
      const response = await fetch('/api/agents', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      const data = await response.json();
      setAgents(data.agents || []);
    } catch (error) {
      console.error('Failed to fetch agents:', error);
    }
  };

  const executeTask = async () => {
    if (!selectedAgent || !task.trim()) return;

    setIsLoading(true);
    setResult('');

    try {
      const response = await fetch(`/api/agents/${selectedAgent.id}/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
        body: JSON.stringify({ task }),
      });

      const data = await response.json();
      if (data.success) {
        setResult(data.result.response);
        setTask('');
        fetchAgents();
      } else {
        setResult(`Error: ${data.error}`);
      }
    } catch (error) {
      setResult(`Failed to execute task: ${error}`);
    } finally {
      setIsLoading(false);
    }
  };

  const getAgentIcon = (type: string) => {
    switch (type) {
      case 'red-team':
        return <Target className="h-5 w-5 text-red-400" />;
      case 'blue-team':
        return <Shield className="h-5 w-5 text-blue-400" />;
      case 'purple-team':
        return <Eye className="h-5 w-5 text-purple-400" />;
      case 'black-hat':
        return <Lock className="h-5 w-5 text-gray-400" />;
      case 'llm-agent':
        return <Terminal className="h-5 w-5 text-cyan-400" />;
      default:
        return <Cpu className="h-5 w-5 text-gray-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-600';
      case 'standby':
        return 'bg-yellow-600';
      case 'offline':
        return 'bg-gray-600';
      default:
        return 'bg-gray-600';
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-6xl h-[80vh] flex flex-col bg-slate-900 border-slate-700">
        <CardHeader className="border-b border-slate-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-gradient-to-br from-purple-600 to-blue-600 rounded-lg">
                <Cpu className="h-5 w-5 text-white" />
              </div>
              <div>
                <CardTitle className="text-white">AI Security Agents</CardTitle>
                <CardDescription className="text-gray-400">
                  Powered by Mixtral 22B - {agents.length} agents available
                </CardDescription>
              </div>
            </div>
            <Button variant="ghost" size="sm" onClick={onClose} className="text-gray-400 hover:text-white">
              ✕
            </Button>
          </div>
        </CardHeader>

        <CardContent className="flex-1 flex gap-4 p-4 overflow-hidden">
          {/* Agents List */}
          <div className="w-1/3 space-y-3 overflow-auto">
            {agents.map((agent) => (
              <Card
                key={agent.id}
                className={`cursor-pointer transition-all ${
                  selectedAgent?.id === agent.id
                    ? 'bg-slate-700 border-purple-500'
                    : 'bg-slate-800 border-slate-700 hover:bg-slate-750'
                }`}
                onClick={() => setSelectedAgent(agent)}
              >
                <CardHeader className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-2">
                      {getAgentIcon(agent.type)}
                      <div>
                        <CardTitle className="text-sm text-white">{agent.name}</CardTitle>
                        <CardDescription className="text-xs text-gray-400">
                          {agent.type.replace('-', ' ')}
                        </CardDescription>
                      </div>
                    </div>
                    <Badge className={getStatusColor(agent.status)}>{agent.status}</Badge>
                  </div>
                </CardHeader>
                <CardContent className="p-4 pt-0">
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between text-gray-400">
                      <span>Tasks</span>
                      <span className="text-white">{agent.stats.tasksCompleted}</span>
                    </div>
                    <div className="flex justify-between text-gray-400">
                      <span>Success Rate</span>
                      <span className="text-green-400">{agent.stats.successRate}%</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Agent Details & Interaction */}
          <div className="flex-1 flex flex-col space-y-4">
            {selectedAgent ? (
              <>
                <Card className="bg-slate-800 border-slate-700">
                  <CardHeader>
                    <div className="flex items-center space-x-3">
                      {getAgentIcon(selectedAgent.type)}
                      <div>
                        <CardTitle className="text-white">{selectedAgent.name}</CardTitle>
                        <CardDescription className="text-gray-400">
                          {selectedAgent.description}
                        </CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div>
                        <p className="text-sm text-gray-400 mb-2">Model</p>
                        <Badge variant="outline" className="text-purple-400 border-purple-400">
                          {selectedAgent.model}
                        </Badge>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400 mb-2">Capabilities</p>
                        <div className="flex flex-wrap gap-2">
                          {selectedAgent.capabilities.map((cap, idx) => (
                            <Badge key={idx} variant="secondary" className="text-xs">
                              {cap}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="flex-1 bg-slate-800 border-slate-700 flex flex-col">
                  <CardHeader>
                    <CardTitle className="text-white text-sm">Execute Task</CardTitle>
                  </CardHeader>
                  <CardContent className="flex-1 flex flex-col space-y-3">
                    <div className="flex space-x-2">
                      <Input
                        value={task}
                        onChange={(e) => setTask(e.target.value)}
                        onKeyPress={(e) => e.key === 'Enter' && !isLoading && executeTask()}
                        placeholder="Enter a security task for this agent..."
                        className="flex-1 bg-slate-900 border-slate-700 text-white"
                        disabled={isLoading || selectedAgent.status === 'offline'}
                      />
                      <Button
                        onClick={executeTask}
                        disabled={isLoading || !task.trim() || selectedAgent.status === 'offline'}
                        className="bg-gradient-to-r from-purple-600 to-blue-600"
                      >
                        {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                      </Button>
                    </div>

                    {result && (
                      <div className="flex-1 overflow-auto bg-slate-900 rounded-lg p-4 border border-slate-700">
                        <pre className="text-sm text-gray-300 whitespace-pre-wrap">{result}</pre>
                      </div>
                    )}

                    {selectedAgent.status === 'offline' && (
                      <p className="text-xs text-red-400">
                        This agent is currently offline and cannot execute tasks.
                      </p>
                    )}
                  </CardContent>
                </Card>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-gray-400">
                <div className="text-center">
                  <Activity className="h-16 w-16 mx-auto mb-4 text-gray-600" />
                  <p>Select an agent to view details and execute tasks</p>
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
