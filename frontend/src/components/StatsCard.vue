<template>
  <div class="bg-dark-900 border border-dark-700 rounded-xl p-6">
    <p class="text-sm text-gray-500 mb-1">{{ label }}</p>
    <p class="text-2xl font-bold" :class="color || 'text-gray-100'">{{ formatted }}</p>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  label: string
  value: number | string
  format?: 'number' | 'currency' | 'none'
  color?: string
}>()

const formatted = computed(() => {
  if (props.format === 'currency') return `$${Number(props.value).toFixed(2)}`
  if (props.format === 'number') return Number(props.value).toLocaleString()
  return props.value
})
</script>
