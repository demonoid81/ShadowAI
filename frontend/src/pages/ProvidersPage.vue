<template>
  <div>
    <div class="flex justify-between items-center mb-6">
      <h2 class="text-2xl font-bold">{{ $t('providers.title') }}</h2>
      <button @click="testAll" :disabled="testing" class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-sm transition-colors disabled:opacity-50">
        {{ testing ? $t('providers.testing') : $t('providers.testAll') }}
      </button>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div v-for="p in providers" :key="p.name" class="bg-dark-900 border border-dark-700 rounded-xl p-5">
        <div class="flex justify-between items-start mb-3">
          <div>
            <h3 class="font-semibold text-lg">{{ p.name }}</h3>
            <p class="text-sm text-gray-500">{{ $t('providers.defaultModel') }}: {{ p.default_model }}</p>
          </div>
          <span v-if="connectivity[p.name]" class="px-2 py-1 rounded text-xs font-medium"
            :class="connectivity[p.name]?.reachable ? 'bg-green-900/40 text-green-400' : 'bg-red-900/40 text-red-400'">
            {{ connectivity[p.name]?.reachable ? $t('providers.reachable') : $t('providers.unreachable') }}
          </span>
          <span v-else class="px-2 py-1 rounded text-xs bg-dark-700 text-gray-500">{{ $t('providers.notChecked') }}</span>
        </div>
        <div class="flex flex-wrap gap-1 mb-3">
          <span v-for="m in p.supported_models" :key="m" class="px-2 py-0.5 bg-dark-800 text-gray-400 rounded text-xs">{{ m }}</span>
        </div>
        <div v-if="connectivity[p.name]" class="text-xs text-gray-500">
          {{ $t('providers.latency') }}: {{ connectivity[p.name]?.latency_ms }}ms
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import axios from 'axios'

const { t } = useI18n()

// Use separate client for /proxy endpoints
const proxyApi = axios.create({ baseURL: '/proxy' })
proxyApi.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

const providers = ref<any[]>([])
const connectivity = ref<Record<string, any>>({})
const testing = ref(false)

async function fetchProviders() {
  const { data } = await proxyApi.get('/providers')
  providers.value = data.providers || []
}

async function fetchConnectivity() {
  try {
    const { data } = await proxyApi.get('/providers/connectivity')
    const results = data.results || []
    for (const r of results) {
      connectivity.value[r.provider] = r
    }
  } catch { /* admin only */ }
}

async function testAll() {
  testing.value = true
  try {
    const { data } = await proxyApi.post('/providers/test')
    const results = data.results || []
    for (const r of results) {
      connectivity.value[r.provider] = r
    }
  } catch { /* ignore */ }
  testing.value = false
}

onMounted(() => {
  fetchProviders()
  fetchConnectivity()
})
</script>
