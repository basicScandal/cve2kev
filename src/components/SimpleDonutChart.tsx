import React from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

interface SimpleDonutChartProps {
  data: {
    [key: string]: number;
  };
  title: string;
  subtitle?: string;
  colors: { [key: string]: string };
}

export function SimpleDonutChart({ data, title, subtitle, colors }: SimpleDonutChartProps) {
  const labels = Object.keys(data);
  const values = Object.values(data);
  const backgroundColors = labels.map(label => {
    const color = colors[label] || colors.Default;
    return color;
  });

  const chartData = {
    labels,
    datasets: [
      {
        data: values,
        backgroundColor: backgroundColors,
        borderColor: 'rgba(17, 24, 39, 0.8)',
        borderWidth: 1,
        hoverOffset: 8,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: {
          color: '#ffffff',
          font: { 
            size: 12,
            weight: '500' as const,
            family: 'system-ui, -apple-system, sans-serif'
          },
          padding: 20,
          generateLabels: (chart: any) => {
            const { data } = chart;
            return data.labels.map((label: string, index: number) => ({
              text: label,
              fillStyle: data.datasets[0].backgroundColor[index],
              strokeStyle: 'rgba(255, 255, 255, 0.15)',
              lineWidth: 1,
              hidden: false,
              index
            }));
          },
          boxWidth: 16,
          boxHeight: 16,
          usePointStyle: true,
          pointStyle: 'circle'
        },
        maxWidth: 300,
        maxHeight: 200
      },
      title: {
        display: true,
        text: [title, subtitle].filter(Boolean),
        color: '#ffffff',
        font: {
          size: 16,
          weight: 'bold',
          family: 'system-ui, -apple-system, sans-serif'
        },
        padding: { bottom: 20 }
      },
      tooltip: {
        backgroundColor: 'rgba(17, 24, 39, 0.95)',
        titleColor: '#ffffff',
        bodyColor: '#d1d5db',
        borderColor: 'rgba(59, 130, 246, 0.2)',
        borderWidth: 1,
        padding: 12,
        displayColors: true,
        callbacks: {
          label: function(context: any) {
            const label = context.label || '';
            const value = context.raw || 0;
            const total = context.dataset.data.reduce((a: number, b: number) => a + b, 0);
            const percentage = ((value / total) * 100).toFixed(1);
            return `${value} vulnerabilities (${percentage}%)`;
          },
          title: function(tooltipItems: any) {
            return tooltipItems[0].label;
          }
        }
      }
    },
    cutout: '65%',
    animation: {
      animateScale: true,
      animateRotate: true,
      duration: 1000
    },
    layout: {
      padding: {
        top: 20,
        bottom: 20,
        left: 20,
        right: 20
      }
    }
  };

  return (
    <div className="h-[400px]">
      <Doughnut data={chartData} options={options} />
    </div>
  );
}