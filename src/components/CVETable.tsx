import React from 'react';
import { ExternalLink } from 'lucide-react';
import { CVE } from '../types/cve';
import { severityColors } from '../utils/colors';

interface CVETableProps {
  cves: CVE[];
}

export function CVETable({ cves }: CVETableProps) {
  return (
    <div className="mt-8 flow-root">
      <div className="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
        <div className="inline-block min-w-full py-2 align-middle">
          <table className="min-w-full divide-y divide-gray-700">
            <thead>
              <tr>
                <th className="px-3 py-3.5 text-left text-sm font-semibold text-white">CVE ID</th>
                <th className="px-3 py-3.5 text-left text-sm font-semibold text-white">Severity</th>
                <th className="px-3 py-3.5 text-left text-sm font-semibold text-white">Description</th>
                <th className="px-3 py-3.5 text-left text-sm font-semibold text-white">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {cves.map((cve) => (
                <tr key={cve.id} className="hover:bg-white/5">
                  <td className="whitespace-nowrap px-3 py-4 text-sm text-cyan-400">{cve.id}</td>
                  <td className="whitespace-nowrap px-3 py-4 text-sm">
                    <span
                      className="px-2 py-1 rounded-full text-white text-xs font-medium"
                      style={{ backgroundColor: severityColors[cve.severity] }}
                    >
                      {cve.severity}
                    </span>
                  </td>
                  <td className="px-3 py-4 text-sm text-gray-300 max-w-xl truncate">
                    {cve.description}
                  </td>
                  <td className="whitespace-nowrap px-3 py-4 text-sm">
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1"
                    >
                      View Details
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}