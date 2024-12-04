import React from 'react';
import { Dashboard } from './components/Dashboard';
import { analyzeCWEDistribution } from './utils/cwe-utils';
import { vulnerabilityData } from './data/vulnerabilities';
import { kevData } from './data/kev-data';

function App() {
  const cweDistribution = analyzeCWEDistribution(vulnerabilityData);

  return (
    <Dashboard
      cweDistribution={cweDistribution}
      kevData={kevData}
      totalVulnerabilities={vulnerabilityData.length}
      exploitedCount={Object.values(kevData).reduce((acc, curr) => acc + curr.count, 0)}
      vulnerabilities={vulnerabilityData}
    />
  );
}

export default App;