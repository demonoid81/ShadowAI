<template>
  <div class="bg-dark-900 border border-dark-700 rounded-xl p-6">
    <h3 class="text-lg font-semibold mb-2">{{ label }}</h3>
    <div class="flex items-end gap-2 mb-3">
      <span class="text-3xl font-bold" :class="percentColor">{{ percent.toFixed(0) }}%</span>
      <span class="text-gray-500 text-sm mb-1">{{ formatValue(spent) }} / {{ formatValue(limit) }}</span>
    </div>
    <div class="w-full bg-dark-700 rounded-full h-3">
      <div class="h-3 rounded-full transition-all" :class="barColor" :style="{ width: Math.min(percent, 100) + '%' }"></div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ label: string; spent: number; limit: number; type?: 'currency' | 'number' }>()

const percent = computed(() => props.limit > 0 ? (props.spent / props.limit) * 100 : 0)
const percentColor = computed(() => percent.value > 90 ? 'text-red-400' : percent.value > 70 ? 'text-yellow-400' : 'text-green-400')
const barColor = computed(() => percent.value > 90 ? 'bg-red-500' : percent.value > 70 ? 'bg-yellow-500' : 'bg-green-500')

function formatValue(v: number) {
  return props.type === 'currency' ? `$${v.toFixed(2)}` : v.toLocaleString()
}
</script>
