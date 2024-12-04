import React from 'react';
import { Search } from 'lucide-react';

interface SearchBarProps {
  value: string;
  onChange: (value: string) => void;
}

export function SearchBar({ value, onChange }: SearchBarProps) {
  return (
    <div className="relative w-full max-w-xl">
      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
        <Search className="h-5 w-5 text-gray-400" />
      </div>
      <input
        type="text"
        className="block w-full pl-10 pr-3 py-2 bg-white/5 border border-cyan-400/20 rounded-md leading-5 text-white placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 focus:border-cyan-400 backdrop-blur-sm"
        placeholder="Search CVEs by ID, severity, or keyword..."
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}