'use client';

import { useState, useRef, useEffect } from 'react';
import { Button } from './button';
import { Copy, Play, Trash2 } from 'lucide-react';
import { cn } from '@/lib/utils';

interface TerminalProps {
  className?: string;
  onCommand?: (command: string) => void;
  readOnly?: boolean;
}

export function Terminal({ className, onCommand, readOnly = false }: TerminalProps) {
  const [history, setHistory] = useState<string[]>([
    '$ Alpha AI Security Terminal v1.0.0',
    '$ Type "help" for available commands',
    '$ ',
  ]);
  const [currentInput, setCurrentInput] = useState('');
  const [isExecuting, setIsExecuting] = useState(false);
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    // Auto-scroll to bottom
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [history]);

  const handleCommand = async (command: string) => {
    if (!command.trim() || isExecuting) return;

    const newHistory = [...history, `$ ${command}`];
    setHistory(newHistory);
    setCurrentInput('');
    setIsExecuting(true);

    try {
      if (onCommand) {
        await onCommand(command);
      }
      
      // Simulate command execution
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setHistory(prev => [...prev, 'Command executed successfully', '$ ']);
    } catch (error) {
      setHistory(prev => [...prev, `Error: ${error}`, '$ ']);
    } finally {
      setIsExecuting(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleCommand(currentInput);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      // Navigate command history
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      // Navigate command history
    }
  };

  const clearTerminal = () => {
    setHistory(['$ Terminal cleared', '$ ']);
    setCurrentInput('');
    inputRef.current?.focus();
  };

  const copyToClipboard = () => {
    const text = history.join('\n');
    navigator.clipboard.writeText(text);
  };

  return (
    <div className={cn('terminal relative', className)}>
      {/* Terminal Header */}
      <div className="flex items-center justify-between border-b border-gray-700 bg-gray-800 px-4 py-2">
        <div className="flex items-center space-x-2">
          <div className="h-3 w-3 rounded-full bg-red-500"></div>
          <div className="h-3 w-3 rounded-full bg-yellow-500"></div>
          <div className="h-3 w-3 rounded-full bg-green-500"></div>
          <span className="ml-2 text-xs text-gray-400">Security Terminal</span>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={copyToClipboard}
            className="h-6 w-6 p-0 text-gray-400 hover:text-white"
          >
            <Copy className="h-3 w-3" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={clearTerminal}
            className="h-6 w-6 p-0 text-gray-400 hover:text-white"
          >
            <Trash2 className="h-3 w-3" />
          </Button>
        </div>
      </div>

      {/* Terminal Content */}
      <div
        ref={terminalRef}
        className="h-96 overflow-y-auto p-4 font-mono text-sm"
        onClick={() => inputRef.current?.focus()}
      >
        {history.map((line, index) => (
          <div key={index} className="mb-1">
            {line.startsWith('$') ? (
              <span className="text-green-400">{line}</span>
            ) : line.startsWith('Error') ? (
              <span className="text-red-400">{line}</span>
            ) : line.startsWith('Command executed') ? (
              <span className="text-blue-400">{line}</span>
            ) : (
              <span className="text-gray-300">{line}</span>
            )}
          </div>
        ))}
        
        {!readOnly && (
          <div className="flex items-center">
            <span className="text-green-400">$ </span>
            <input
              ref={inputRef}
              type="text"
              value={currentInput}
              onChange={(e) => setCurrentInput(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={isExecuting}
              className="terminal-input flex-1 outline-none"
              placeholder={isExecuting ? 'Executing...' : 'Enter command...'}
              autoFocus
            />
            {isExecuting && (
              <span className="ml-2 text-yellow-400">
                <span className="loading-dots"></span>
              </span>
            )}
          </div>
        )}
      </div>

      {/* Terminal Footer */}
      {!readOnly && (
        <div className="border-t border-gray-700 bg-gray-800 px-4 py-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4 text-xs text-gray-400">
              <span>Available: scan, analyze, exploit, help</span>
              <span>•</span>
              <span>Press Enter to execute</span>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleCommand('help')}
              className="h-6 text-xs text-gray-400 hover:text-white"
            >
              <Play className="mr-1 h-3 w-3" />
              Quick Help
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
