import { KEVCWEData } from '../types/kev';
import { getVulnerabilityColor } from './colors';

export const kevCweColors = new Proxy({}, {
  get: (target, prop) => {
    if (typeof prop === 'string') {
      return getVulnerabilityColor(prop);
    }
    return getVulnerabilityColor('Default');
  }
});

export function transformKEVData(kevData: KEVCWEData): { [key: string]: number } {
  return Object.entries(kevData).reduce((acc, [cweId, data]) => {
    const description = data.description.split('.')[0].trim();
    acc[description] = data.count;
    return acc;
  }, {} as { [key: string]: number });
}