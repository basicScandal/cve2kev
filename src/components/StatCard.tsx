import React from 'react';

interface StatCardProps {
  value: number;
  label: string;
}

export function StatCard({ value, label }: StatCardProps) {
  return (
    <div className="bg-white/5 p-6 rounded-lg border border-cyan-400/20 backdrop-blur-sm">
      <p className="text-3xl font-bold text-white mb-1">{value}</p>
      <p className="text-gray-400 text-sm">{label}</p>
    </div>
  );
}