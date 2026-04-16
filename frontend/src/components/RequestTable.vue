<template>
  <div class="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-dark-700 text-left text-gray-500">
            <th class="px-4 py-3">Time</th>
            <th class="px-4 py-3">Model</th>
            <th class="px-4 py-3">Tokens</th>
            <th class="px-4 py-3">Cost</th>
            <th class="px-4 py-3">PII</th>
            <th class="px-4 py-3">Policy</th>
            <th class="px-4 py-3">Status</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="log in logs" :key="log.id" class="border-b border-dark-800 hover:bg-dark-800/50">
            <td class="px-4 py-3 text-gray-400">{{ new Date(log.created_at).toLocaleString() }}</td>
            <td class="px-4 py-3">{{ log.model }}</td>
            <td class="px-4 py-3 text-gray-400">{{ log.total_tokens }}</td>
            <td class="px-4 py-3 text-green-400">${{ log.cost_usd?.toFixed(4) }}</td>
            <td class="px-4 py-3">
              <span v-if="log.pii_detected" class="text-red-400">Yes</span>
              <span v-else class="text-gray-600">No</span>
            </td>
            <td class="px-4 py-3">
              <span :class="policyClass(log.policy_action)" class="px-2 py-0.5 rounded text-xs font-medium">
                {{ log.policy_action }}
              </span>
            </td>
            <td class="px-4 py-3">{{ log.status_code }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{ logs: any[] }>()

function policyClass(action: string) {
  if (action === 'blocked') return 'bg-red-900/50 text-red-400'
  if (action === 'sanitized') return 'bg-orange-900/50 text-orange-400'
  if (action === 'warned') return 'bg-yellow-900/50 text-yellow-400'
  if (action === 'allowed') return 'bg-green-900/50 text-green-400'
  // Любой неопознанный action НЕ показываем как allowed — явный серый цвет,
  // чтобы не терять seсurity-события (например, новые типы action'ов).
  return 'bg-dark-700 text-gray-400'
}
</script>
