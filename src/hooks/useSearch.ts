import { useState, useMemo } from 'react';
import { CVE } from '../types/cve';

export function useSearch(items: CVE[]) {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredItems = useMemo(() => 
    items.filter(item =>
      item.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.severity.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.description.toLowerCase().includes(searchTerm.toLowerCase())
    ),
    [items, searchTerm]
  );

  return {
    searchTerm,
    setSearchTerm,
    filteredItems
  };
}