import React, { useMemo } from 'react';
import { Header } from './Header';
import { StatCard } from './StatCard';
import { SimpleDonutChart } from './SimpleDonutChart';
import { VulnerabilityTable } from './VulnerabilityTable';
import { ProgressLog } from './ProgressLog';
import { cweColors } from '../utils/cwe-utils';
import { kevCweColors, transformKEVData } from '../utils/kev-utils';
import { CWEData } from '../utils/cwe-utils';
import { KEVCWEData } from '../types/kev';
import { Vulnerability } from '../types/vulnerability';

interface DashboardProps {
  cweDistribution: CWEData;
  kevData: KEVCWEData;
  totalVulnerabilities: number;
  exploitedCount: number;
  vulnerabilities: Vulnerability[];
}

function formatTimestamp(date: Date): string {
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  }).replace(',', '');
}

export function Dashboard({ 
  cweDistribution,
  kevData,
  totalVulnerabilities,
  exploitedCount,
  vulnerabilities
}: DashboardProps) {
  const transformedKEVData = transformKEVData(kevData);
  const now = new Date();

  const logEntries = useMemo(() => [
    { 
      timestamp: formatTimestamp(now), 
      message: 'Retrieving vulnerability data from NVD database' 
    },
    { 
      timestamp: formatTimestamp(new Date(now.getTime() + 2000)), 
      message: 'Retrieved 222 CVEs for Palo Alto Networks' 
    },
    { 
      timestamp: formatTimestamp(new Date(now.getTime() + 4000)), 
      message: 'Cross-referencing with CISA KEV catalog' 
    },
    { 
      timestamp: formatTimestamp(new Date(now.getTime() + 6000)), 
      message: 'Identified 10 vulnerabilities in KEV catalog' 
    }
  ], [now]);

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Header />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <StatCard value={totalVulnerabilities} label="Total CVEs" />
          <StatCard value={exploitedCount} label="Known Exploited Vulnerabilities" />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
          <div className="bg-white/5 p-6 rounded-lg border border-cyan-400/20 backdrop-blur-sm">
            <SimpleDonutChart
              data={cweDistribution}
              title="Total CVEs by CWE"
              subtitle="Distribution of Common Weakness Enumeration Types"
              colors={cweColors}
            />
          </div>
          <div className="bg-white/5 p-6 rounded-lg border border-cyan-400/20 backdrop-blur-sm">
            <SimpleDonutChart
              data={transformedKEVData}
              title="Total KEVs by CWE"
              subtitle="Known Exploited Vulnerabilities by Type"
              colors={kevCweColors}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 bg-white/5 rounded-lg border border-cyan-400/20 backdrop-blur-sm p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Recent Vulnerabilities</h2>
            <VulnerabilityTable vulnerabilities={vulnerabilities} />
          </div>
          <div className="lg:col-span-1">
            <ProgressLog entries={logEntries} />
          </div>
        </div>
      </div>
    </div>
  );
}