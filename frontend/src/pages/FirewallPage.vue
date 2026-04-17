<template>
  <div>
    <h2 class="text-2xl font-bold mb-6">{{ $t('firewall.title') }}</h2>

    <!-- Inspector Pipeline -->
    <div class="bg-dark-900 border border-dark-700 rounded-xl p-6 mb-6">
      <h3 class="text-lg font-semibold mb-4">{{ $t('firewall.pipeline') }}</h3>
      <div v-if="loading" class="text-gray-500 text-sm">{{ $t('firewall.loading') }}</div>
      <div v-else-if="!firewallEnabled" class="text-gray-500 text-sm">{{ $t('firewall.notEnabled') }}</div>
      <div v-else class="space-y-2">
        <div v-for="(inspector, i) in inspectors" :key="inspector.name"
          class="flex items-center justify-between px-4 py-3 bg-dark-800 rounded-lg">
          <div class="flex items-center gap-3">
            <span class="w-6 h-6 rounded-full bg-primary-600/30 text-primary-400 flex items-center justify-center text-xs font-bold">{{ i + 1 }}</span>
            <span class="font-medium">{{ inspectorLabel(inspector.name) }}</span>
          </div>
          <div class="flex items-center gap-3 text-sm">
            <span class="text-gray-500">{{ $t('firewall.' + inspector.phase) }}</span>
            <span class="px-2 py-0.5 rounded text-xs font-mono" :class="modeClass(inspector.mode)"
              :title="$t('firewall.mode')">
              {{ modeLabel(inspector.mode) }}
            </span>
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
            <th class="px-4 py-2">{{ $t('firewall.endpoint') }}</th>
            <th class="px-4 py-2">{{ $t('firewall.provider') }}</th>
            <th class="px-4 py-2">{{ $t('firewall.statusCode') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in blocks" :key="b.id" class="border-b border-dark-800">
            <td class="px-4 py-2 text-gray-500">{{ new Date(b.created_at).toLocaleString() }}</td>
            <td class="px-4 py-2">{{ b.user_id?.slice(0, 8) }}...</td>
            <td class="px-4 py-2 text-gray-400">{{ b.model || '-' }}</td>
            <td class="px-4 py-2 text-gray-400">{{ b.endpoint || '-' }}</td>
            <td class="px-4 py-2 text-gray-400">{{ b.provider || '-' }}</td>
            <td class="px-4 py-2 text-red-400">{{ b.status_code || '-' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import api, { proxyApi } from '../api/client'

const { t } = useI18n()

interface InspectorInfo {
  name: string
  enabled: boolean
  phase: string
  // PR-4: runtime-режим инспектора. backend возвращает `mode` в
  // /proxy/firewall/status (см. backend/internal/firewall/status.go).
  // Отсутствует только у старых бэкендов → fallback на "enforce" в modeLabel.
  mode?: string
}

const nameToLabelKey: Record<string, string> = {
  pii: 'firewall.pii',
  dlp: 'firewall.dlp',
  policy: 'firewall.policy',
  prompt_injection: 'firewall.promptInjection',
  jailbreak: 'firewall.jailbreak',
  content_moderation: 'firewall.contentModeration',
  output_validation: 'firewall.outputValidation',
  content_ratelimit: 'firewall.contentRateLimit',
  multiturn: 'firewall.multiTurn',
  semantic: 'firewall.semantic',
}

function inspectorLabel(name: string): string {
  const key = nameToLabelKey[name]
  return key ? t(key) : name
}

// modeClass — цветовая схема для mode badge.
// enforce — нейтрально серый (стандартный режим, не должен визуально шуметь).
// shadow — жёлтый (сигнал: инспектор наблюдает, но не блокирует).
// disabled — тёмно-серый с приглушённым текстом (отключён оператором).
// fallback — нейтральный серый для неизвестных значений с бэкенда.
function modeClass(mode: string | undefined): string {
  switch (mode) {
    case 'shadow':
      return 'bg-yellow-900/40 text-yellow-400'
    case 'disabled':
      return 'bg-dark-700 text-gray-500'
    case 'enforce':
    default:
      return 'bg-dark-700 text-gray-300'
  }
}

function modeLabel(mode: string | undefined): string {
  switch (mode) {
    case 'shadow':
      return t('firewall.modeShadow')
    case 'disabled':
      return t('firewall.modeDisabled')
    case 'enforce':
    default:
      return t('firewall.modeEnforce')
  }
}

const loading = ref(true)
const firewallEnabled = ref(false)
const inspectors = ref<InspectorInfo[]>([])
const blocks = ref<any[]>([])

async function fetchFirewallStatus() {
  try {
    const { data } = await proxyApi.get('/firewall/status')
    firewallEnabled.value = data.enabled
    inspectors.value = data.inspectors || []
  } catch {
    firewallEnabled.value = false
    inspectors.value = []
  } finally {
    loading.value = false
  }
}

async function fetchBlocks() {
  try {
    const { data } = await api.get('/audit/logs', { params: { policy_action: 'blocked', limit: 20 } })
    blocks.value = data.data || []
  } catch { /* admin only */ }
}

onMounted(() => {
  fetchFirewallStatus()
  fetchBlocks()
})
</script>
