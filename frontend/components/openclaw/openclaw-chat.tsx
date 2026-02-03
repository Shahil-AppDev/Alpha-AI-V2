'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { useAuth } from '@/lib/auth-context';
import { Bot, Loader2, MessageSquare, Send, User, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

interface Message {
  id: string;
  content: string;
  sender: 'user' | 'assistant';
  timestamp: Date;
}

interface OpenClawChatProps {
  isOpen: boolean;
  onClose: () => void;
}

export function OpenClawChat({ isOpen, onClose }: OpenClawChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  useAuth();

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  useEffect(() => {
    checkConnection();
  }, [isOpen]);

  const checkConnection = async () => {
    try {
      const response = await fetch('/api/openclaw/status', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      const data = await response.json();
      setIsConnected(data.connected);
    } catch (error) {
      console.error('Failed to check OpenClaw connection:', error);
      setIsConnected(false);
    }
  };

  const sendMessage = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: `user_${Date.now()}`,
      content: input,
      sender: 'user',
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await fetch('/api/openclaw/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
        body: JSON.stringify({ message: input }),
      });

      const data = await response.json();

      const assistantMessage: Message = {
        id: `assistant_${Date.now()}`,
        content: data.message || data.error || 'No response from assistant',
        sender: 'assistant',
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (error) {
      console.error('Failed to send message:', error);
      const errorMessage: Message = {
        id: `error_${Date.now()}`,
        content: 'Failed to communicate with OpenClaw assistant. Please try again.',
        sender: 'assistant',
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-2xl h-[600px] flex flex-col bg-slate-900 border-slate-700">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4 border-b border-slate-700">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-gradient-to-br from-purple-600 to-blue-600 rounded-lg">
              <MessageSquare className="h-5 w-5 text-white" />
            </div>
            <div>
              <CardTitle className="text-white">OpenClaw AI Assistant</CardTitle>
              <CardDescription className="text-gray-400">
                AI-powered security assistant with access to all tools
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Badge variant={isConnected ? 'default' : 'destructive'} className="text-xs">
              {isConnected ? 'Connected' : 'Disconnected'}
            </Badge>
            <Button
              variant="ghost"
              size="sm"
              onClick={onClose}
              className="text-gray-400 hover:text-white"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </CardHeader>

        <CardContent className="flex-1 flex flex-col p-0">
          <div className="flex-1 p-4 overflow-auto" ref={scrollRef}>
            {messages.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-center space-y-4">
                <Bot className="h-16 w-16 text-purple-400" />
                <div>
                  <h3 className="text-lg font-semibold text-white mb-2">
                    Welcome to OpenClaw Assistant
                  </h3>
                  <p className="text-sm text-gray-400 max-w-md">
                    I have access to all security tools including network scanning, code analysis,
                    exploit generation, password cracking, and more. How can I help you today?
                  </p>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                {messages.map((message) => (
                  <div
                    key={message.id}
                    className={`flex items-start space-x-3 ${
                      message.sender === 'user' ? 'flex-row-reverse space-x-reverse' : ''
                    }`}
                  >
                    <div
                      className={`p-2 rounded-lg ${
                        message.sender === 'user'
                          ? 'bg-blue-600'
                          : 'bg-gradient-to-br from-purple-600 to-blue-600'
                      }`}
                    >
                      {message.sender === 'user' ? (
                        <User className="h-4 w-4 text-white" />
                      ) : (
                        <Bot className="h-4 w-4 text-white" />
                      )}
                    </div>
                    <div
                      className={`flex-1 ${
                        message.sender === 'user' ? 'text-right' : 'text-left'
                      }`}
                    >
                      <div
                        className={`inline-block p-3 rounded-lg ${
                          message.sender === 'user'
                            ? 'bg-blue-600 text-white'
                            : 'bg-slate-800 text-gray-200'
                        }`}
                      >
                        <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                      </div>
                      <p className="text-xs text-gray-500 mt-1">
                        {message.timestamp.toLocaleTimeString()}
                      </p>
                    </div>
                  </div>
                ))}
                {isLoading && (
                  <div className="flex items-start space-x-3">
                    <div className="p-2 rounded-lg bg-gradient-to-br from-purple-600 to-blue-600">
                      <Bot className="h-4 w-4 text-white" />
                    </div>
                    <div className="flex-1">
                      <div className="inline-block p-3 rounded-lg bg-slate-800">
                        <Loader2 className="h-4 w-4 animate-spin text-purple-400" />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="p-4 border-t border-slate-700">
            <div className="flex space-x-2">
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Ask me anything about security tools..."
                className="flex-1 bg-slate-800 border-slate-700 text-white placeholder:text-gray-500"
                disabled={isLoading || !isConnected}
              />
              <Button
                onClick={sendMessage}
                disabled={isLoading || !input.trim() || !isConnected}
                className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700"
              >
                {isLoading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Send className="h-4 w-4" />
                )}
              </Button>
            </div>
            {!isConnected && (
              <p className="text-xs text-red-400 mt-2">
                OpenClaw assistant is not connected. Please check the server status.
              </p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
