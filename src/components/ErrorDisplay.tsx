import React from 'react';
import { AlertCircle } from 'lucide-react';

interface ErrorDisplayProps {
  message: string;
}

export function ErrorDisplay({ message }: ErrorDisplayProps) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="bg-red-900/50 p-4 rounded-md border border-red-500/20 backdrop-blur-sm">
        <div className="flex items-center">
          <AlertCircle className="h-5 w-5 text-red-400" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-200">Error</h3>
            <div className="mt-2 text-sm text-red-300">{message}</div>
          </div>
        </div>
      </div>
    </div>
  );
}