import React from 'react';
import { Chart, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import { kevCweColors, formatCWELabel } from '../utils/kev-utils';
import type { KEVCWEData } from '../types/kev';

// Register chart components manually
Chart.register(ArcElement, Tooltip, Legend);

interface KEVCWEChartProps {
  data: KEVCWEData;
  title: string;
}

export function KEVCWEChart({ data, title }: KEVCWEChartProps) {
  const labels = Object.entries(data).map(([cweId, info]) => 
    formatCWELabel(cweId, info.description)
  );
  const values = Object.values(data).map(info => info.count);
  const colors = Object.keys(data).map(cweId => kevCweColors[cweId] || kevCweColors.Default);

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
            const cweId = Object.keys(data)[context.dataIndex];
            const info = data[cweId];
            return [
              `Count: ${info.count}`,
              `Description: ${info.description}`
            ];
          }
        }
      }
    },
  };

  return <Doughnut data={chartData} options={options} />;
}