<template>
  <div class="bg-dark-900 border border-dark-700 rounded-xl p-6">
    <h3 class="text-lg font-semibold mb-4">Usage Over Time</h3>
    <Line v-if="chartData" :data="chartData" :options="chartOptions" />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Line } from 'vue-chartjs'
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler } from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler)

const props = defineProps<{ data: Array<{ date: string; requests: number; cost: number }> }>()

const chartData = computed(() => {
  if (!props.data.length) return null
  return {
    labels: props.data.map(d => d.date),
    datasets: [
      {
        label: 'Requests',
        data: props.data.map(d => d.requests),
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59,130,246,0.1)',
        fill: true,
        tension: 0.3,
        yAxisID: 'y'
      },
      {
        label: 'Cost ($)',
        data: props.data.map(d => d.cost),
        borderColor: '#10b981',
        backgroundColor: 'rgba(16,185,129,0.1)',
        fill: true,
        tension: 0.3,
        yAxisID: 'y1'
      }
    ]
  }
})

const chartOptions = {
  responsive: true,
  interaction: { intersect: false, mode: 'index' as const },
  scales: {
    x: { ticks: { color: '#6b7280' }, grid: { color: '#1f2937' } },
    y: { position: 'left' as const, ticks: { color: '#3b82f6' }, grid: { color: '#1f2937' } },
    y1: { position: 'right' as const, ticks: { color: '#10b981' }, grid: { drawOnChartArea: false } }
  },
  plugins: { legend: { labels: { color: '#d1d5db' } } }
}
</script>
