import { useState, useEffect } from 'react';
import { fetchPaloAltoCVEs, fetchExploitedCVEs } from '../services/api';
import { CVE, CVEStats } from '../types/cve';

export function useCVEData() {
  const [cves, setCVEs] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<CVEStats>({
    total: 0,
    exploited: 0,
    bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  });

  useEffect(() => {
    async function loadData() {
      try {
        const [allCVEs, exploitedCVEIds] = await Promise.all([
          fetchPaloAltoCVEs(),
          fetchExploitedCVEs(),
        ]);

        const updatedCVEs = allCVEs.map(cve => ({
          ...cve,
          exploited: exploitedCVEIds.includes(cve.id),
        }));

        setCVEs(updatedCVEs);
        
        const newStats = {
          total: updatedCVEs.length,
          exploited: exploitedCVEIds.length,
          bySeverity: {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
          },
        };

        updatedCVEs.forEach(cve => {
          newStats.bySeverity[cve.severity]++;
        });

        setStats(newStats);
        setError(null);
      } catch (error) {
        setError(error instanceof Error ? error.message : 'An error occurred while fetching data');
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, []);

  return { cves, loading, error, stats };
}