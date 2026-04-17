<template>
  <div>
    <h2 class="text-2xl font-bold mb-6">{{ $t('audit.title') }}</h2>
    <div class="flex gap-4 mb-6">
      <select v-model="filters.policy_action" @change="load" class="px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 text-sm">
        <option value="">{{ $t('audit.allActions') }}</option>
        <option value="allowed">{{ $t('audit.allowed') }}</option>
        <option value="blocked">{{ $t('audit.blocked') }}</option>
        <option value="warned">{{ $t('audit.warned') }}</option>
        <option value="sanitized">{{ $t('audit.sanitized') }}</option>
      </select>
      <select v-model="filters.has_shadow" @change="load" class="px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 text-sm">
        <option value="">{{ $t('audit.shadowAny') }}</option>
        <option value="yes">{{ $t('audit.shadowYes') }}</option>
        <option value="no">{{ $t('audit.shadowNo') }}</option>
      </select>
      <input v-model="filters.model" @input="load" :placeholder="t('audit.filterModel')" class="px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 text-sm" />
    </div>
    <RequestTable :logs="store.logs" />
    <div class="flex justify-between items-center mt-4 text-sm text-gray-500">
      <span>{{ $t('audit.total', { count: store.total }) }}</span>
      <div class="flex gap-2">
        <button @click="prevPage" :disabled="offset === 0" class="px-3 py-1 bg-dark-800 rounded disabled:opacity-50">{{ $t('audit.prev') }}</button>
        <button @click="nextPage" :disabled="offset + 50 >= store.total" class="px-3 py-1 bg-dark-800 rounded disabled:opacity-50">{{ $t('audit.next') }}</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuditStore } from '../stores/audit'
import RequestTable from '../components/RequestTable.vue'

const { t } = useI18n()
const store = useAuditStore()
const offset = ref(0)
// has_shadow: '' = any (backend игнорирует невалидные значения);
// 'yes' = только записи с shadow-решениями, 'no' = без. См. backend/internal/audit/handler.go.
const filters = reactive({ policy_action: '', model: '', has_shadow: '' })

function load() {
  // Отсекаем пустые параметры, чтобы не засорять query string (и чтобы сервер
  // воспринимал отсутствие фильтра, а не пустую строку как фильтр).
  const params: Record<string, any> = { offset: offset.value, limit: 50 }
  for (const [k, v] of Object.entries(filters)) {
    if (v) params[k] = v
  }
  store.fetchLogs(params)
}
function prevPage() { offset.value = Math.max(0, offset.value - 50); load() }
function nextPage() { offset.value += 50; load() }

onMounted(load)
</script>
