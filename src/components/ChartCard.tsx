import React from 'react';
import { DonutChart } from './DonutChart';

interface ChartCardProps {
  data: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  title: string;
}

export function ChartCard({ data, title }: ChartCardProps) {
  return (
    <div className="bg-white/5 p-6 rounded-lg border border-cyan-400/20 backdrop-blur-sm">
      <div className="h-[300px] flex items-center justify-center">
        <DonutChart data={data} title={title} />
      </div>
    </div>
  );
}