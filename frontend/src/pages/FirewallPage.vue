<template>
  <div>
    <h2 class="text-2xl font-bold mb-6">{{ $t('firewall.title') }}</h2>

    <!-- Inspector Pipeline -->
    <div class="bg-dark-900 border border-dark-700 rounded-xl p-6 mb-6">
      <h3 class="text-lg font-semibold mb-4">{{ $t('firewall.pipeline') }}</h3>
      <div class="space-y-2">
        <div v-for="(inspector, i) in inspectors" :key="i"
          class="flex items-center justify-between px-4 py-3 bg-dark-800 rounded-lg">
          <div class="flex items-center gap-3">
            <span class="w-6 h-6 rounded-full bg-primary-600/30 text-primary-400 flex items-center justify-center text-xs font-bold">{{ i + 1 }}</span>
            <span class="font-medium">{{ $t(inspector.labelKey) }}</span>
          </div>
          <div class="flex items-center gap-4 text-sm">
            <span class="text-gray-500">{{ $t('firewall.' + inspector.phase) }}</span>
            <span class="px-2 py-0.5 rounded text-xs"
              :class="inspector.enabled ? 'bg-green-900/40 text-green-400' : 'bg-dark-700 text-gray-500'">
              {{ inspector.enabled ? $t('firewall.enabled') : $t('firewall.disabled') }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- Recent Blocks -->
    <div class="bg-dark-900 border border-dark-700 rounded-xl p-6">
      <h3 class="text-lg font-semibold mb-4">{{ $t('firewall.recentBlocks') }}</h3>
      <div v-if="blocks.length === 0" class="text-gray-500 text-sm">{{ $t('firewall.noBlocks') }}</div>
      <table v-else class="w-full text-sm">
        <thead>
          <tr class="text-left text-gray-500 border-b border-dark-700">
            <th class="px-4 py-2">{{ $t('firewall.timestamp') }}</th>
            <th class="px-4 py-2">{{ $t('firewall.user') }}</th>
            <th class="px-4 py-2">{{ $t('audit.model') }}</th>
            <th class="px-4 py-2">{{ $t('firewall.reason') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in blocks" :key="b.id" class="border-b border-dark-800">
            <td class="px-4 py-2 text-gray-500">{{ new Date(b.created_at).toLocaleString() }}</td>
            <td class="px-4 py-2">{{ b.user_id?.slice(0, 8) }}...</td>
            <td class="px-4 py-2 text-gray-400">{{ b.model }}</td>
            <td class="px-4 py-2 text-red-400">{{ b.policy_action }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '../api/client'

const { t } = useI18n()

const inspectors = [
  { labelKey: 'firewall.pii', phase: 'both', enabled: true },
  { labelKey: 'firewall.dlp', phase: 'both', enabled: true },
  { labelKey: 'firewall.policy', phase: 'request', enabled: true },
  { labelKey: 'firewall.promptInjection', phase: 'request', enabled: true },
  { labelKey: 'firewall.jailbreak', phase: 'request', enabled: true },
  { labelKey: 'firewall.contentModeration', phase: 'both', enabled: true },
  { labelKey: 'firewall.outputValidation', phase: 'response', enabled: true },
  { labelKey: 'firewall.contentRateLimit', phase: 'request', enabled: true },
  { labelKey: 'firewall.multiTurn', phase: 'request', enabled: true },
  { labelKey: 'firewall.semantic', phase: 'request', enabled: true }
]

const blocks = ref<any[]>([])

async function fetchBlocks() {
  try {
    const { data } = await api.get('/audit/logs', { params: { policy_action: 'blocked', limit: 20 } })
    blocks.value = data.data || []
  } catch { /* admin only */ }
}

onMounted(fetchBlocks)
</script>
