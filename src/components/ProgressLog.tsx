import React from 'react';
import { Clock } from 'lucide-react';

interface LogEntry {
  timestamp: string;
  message: string;
}

interface ProgressLogProps {
  entries: LogEntry[];
}

export function ProgressLog({ entries }: ProgressLogProps) {
  return (
    <div className="bg-white/5 rounded-lg border border-cyan-400/20 backdrop-blur-sm p-6">
      <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <Clock className="h-5 w-5 text-cyan-400" />
        Progress Log
      </h2>
      <div className="space-y-3">
        {entries.map((entry, index) => (
          <div key={index} className="flex items-start gap-3">
            <div className="text-sm text-gray-400">{entry.timestamp}</div>
            <div className="text-sm text-gray-300">{entry.message}</div>
          </div>
        ))}
      </div>
    </div>
  );
}