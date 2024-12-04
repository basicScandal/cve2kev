import React from 'react';
import { Shield } from 'lucide-react';

export function Header() {
  return (
    <div className="flex items-center gap-3 mb-12">
      <Shield className="h-8 w-8 text-cyan-400" />
      <h1 className="text-2xl font-bold text-white">
        Palo Alto Networks Vulnerability Intelligence 2024
      </h1>
    </div>
  );
}