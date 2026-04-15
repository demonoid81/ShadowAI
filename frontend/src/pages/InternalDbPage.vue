<template>
  <div>
    <h2 class="text-2xl font-bold mb-6">{{ $t('internalDb.title') }}</h2>

    <!-- Sources Section -->
    <div class="bg-dark-900 border border-dark-700 rounded-xl p-6 mb-6">
      <div class="flex justify-between items-center mb-4">
        <h3 class="text-lg font-semibold text-gray-100">{{ $t('internalDb.sources') }}</h3>
        <button @click="fetchSources"
          class="px-3 py-1 text-primary-400 hover:bg-primary-900/30 rounded text-sm transition-colors">
          {{ $t('internalDb.refresh') }}
        </button>
      </div>
      <p v-if="sources.length === 0" class="text-gray-500 text-sm">{{ $t('internalDb.noSources') }}</p>
      <div v-else class="space-y-2">
        <div v-for="source in sources" :key="source.id"
          class="flex items-center justify-between px-4 py-3 bg-dark-800 rounded-lg border border-dark-700">
          <div>
            <span class="text-gray-100 font-medium">{{ source.name }}</span>
            <span v-if="source.description" class="text-gray-500 text-sm ml-2">{{ source.description }}</span>
          </div>
          <div class="flex items-center gap-3">
            <span :class="source.is_active ? 'text-green-400' : 'text-red-400'" class="text-xs">
              {{ source.is_active ? $t('internalDb.connected') : $t('internalDb.connectionFailed') }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- Query Section -->
    <div class="bg-dark-900 border border-dark-700 rounded-xl p-6 mb-6">
      <h3 class="text-lg font-semibold text-gray-100 mb-4">{{ $t('internalDb.query') }}</h3>
      <form @submit.prevent="runQuery" class="space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label class="block text-sm text-gray-400 mb-1">{{ $t('internalDb.source') }}</label>
            <select v-model="queryForm.source_id"
              class="w-full px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 focus:border-primary-500 focus:outline-none">
              <option v-for="source in activeSources" :key="source.id" :value="source.id">
                {{ source.name }}
              </option>
            </select>
          </div>
          <div>
            <label class="block text-sm text-gray-400 mb-1">{{ $t('internalDb.maxRows') }}</label>
            <input v-model.number="queryForm.max_rows" type="number" min="1" max="10000"
              class="w-full px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 focus:border-primary-500 focus:outline-none" />
          </div>
          <div class="flex items-end">
            <button type="submit" :disabled="queryLoading || !queryForm.source_id"
              class="w-full py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white font-medium transition-colors disabled:opacity-50">
              {{ queryLoading ? $t('internalDb.running') : $t('internalDb.runQuery') }}
            </button>
          </div>
        </div>
        <div>
          <label class="block text-sm text-gray-400 mb-1">SQL</label>
          <textarea v-model="queryForm.sql" rows="4" required
            class="w-full px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 font-mono text-sm focus:border-primary-500 focus:outline-none resize-y"></textarea>
        </div>
      </form>
    </div>

    <!-- Results Section -->
    <div v-if="queryResult" class="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
      <div class="flex items-center justify-between px-4 py-3 border-b border-dark-700">
        <div class="flex items-center gap-4 text-sm text-gray-400">
          <span>{{ queryResult.row_count }} {{ $t('internalDb.rows') }}</span>
          <span v-if="queryResult.duration_ms">{{ queryResult.duration_ms }}ms</span>
        </div>
        <span v-if="queryResult.truncated" class="text-yellow-400 text-sm">
          {{ $t('internalDb.truncated') }}
        </span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-dark-700 text-left text-gray-500">
              <th v-for="col in queryResult.columns" :key="col" class="px-4 py-3 whitespace-nowrap">{{ col }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(row, idx) in queryResult.rows" :key="idx" class="border-b border-dark-800 hover:bg-dark-800/50">
              <td v-for="col in queryResult.columns" :key="col" class="px-4 py-3 whitespace-nowrap text-gray-100">
                {{ row[col] }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Query Error -->
    <div v-if="queryError" class="bg-dark-900 border border-red-900/50 rounded-xl p-4">
      <p class="text-red-400 text-sm">{{ queryError }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '../api/client'

const { t } = useI18n()

const sources = ref<any[]>([])
const queryLoading = ref(false)
const queryResult = ref<any>(null)
const queryError = ref('')
const queryForm = reactive({
  source_id: '',
  sql: '',
  max_rows: 100
})

const activeSources = computed(() => sources.value.filter(s => s.is_active))

async function fetchSources() {
  try {
    const { data } = await api.get('/internal-dbs')
    sources.value = data
    if (activeSources.value.length > 0 && !queryForm.source_id) {
      queryForm.source_id = activeSources.value[0].id
    }
  } catch {
    sources.value = []
  }
}

async function runQuery() {
  queryLoading.value = true
  queryResult.value = null
  queryError.value = ''
  try {
    const { data } = await api.post('/internal-dbs/query', {
      source_id: queryForm.source_id,
      sql: queryForm.sql,
      max_rows: queryForm.max_rows
    })
    queryResult.value = data
  } catch (e: any) {
    queryError.value = e.response?.data?.error || t('common.error')
  } finally {
    queryLoading.value = false
  }
}

onMounted(fetchSources)
</script>
