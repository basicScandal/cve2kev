import React from 'react';
import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { cweColors } from '../utils/cwe-utils';
import type { CWEData } from '../utils/cwe-utils';

ChartJS.register(ArcElement, Tooltip, Legend);

interface CWEChartProps {
  data: CWEData;
  title: string;
}

export function CWEChart({ data, title }: CWEChartProps) {
  const labels = Object.keys(data);
  const values = Object.values(data);
  const colors = labels.map(label => cweColors[label] || cweColors.Default);

  const chartData = {
    labels,
    datasets: [
      {
        data: values,
        backgroundColor: colors,
        borderColor: 'rgba(17, 24, 39, 0.8)',
        borderWidth: 1,
      },
    ],
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: {
          color: '#f3f4f6',
          font: { size: 11 },
          padding: 20,
          generateLabels: (chart: any) => {
            const { data } = chart;
            return data.labels.map((label: string, index: number) => ({
              text: `${label} (${data.datasets[0].data[index]})`,
              fillStyle: data.datasets[0].backgroundColor[index],
              hidden: false,
              index
            }));
          }
        }
      },
      title: {
        display: true,
        text: title,
        color: '#f3f4f6',
        font: {
          size: 16,
          weight: 'bold'
        },
        padding: { bottom: 20 }
      },
      tooltip: {
        backgroundColor: 'rgba(17, 24, 39, 0.8)',
        titleColor: '#f3f4f6',
        bodyColor: '#d1d5db',
        borderColor: 'rgba(59, 130, 246, 0.2)',
        borderWidth: 1,
        padding: 12,
        callbacks: {
          label: function(context: any) {
            const label = context.label || '';
            const value = context.raw || 0;
            return `${label}: ${value} vulnerabilities`;
          }
        }
      }
    },
  };

  return <Doughnut data={chartData} options={options} />;
}