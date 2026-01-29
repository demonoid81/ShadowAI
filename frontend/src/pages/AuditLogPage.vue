<template>
  <div>
    <h2 class="text-2xl font-bold mb-6">Audit Logs</h2>
    <div class="flex gap-4 mb-6">
      <select v-model="filters.policy_action" @change="load" class="px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 text-sm">
        <option value="">All Actions</option>
        <option value="allowed">Allowed</option>
        <option value="blocked">Blocked</option>
        <option value="warned">Warned</option>
      </select>
      <input v-model="filters.model" @input="load" placeholder="Filter by model..." class="px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 text-sm" />
    </div>
    <RequestTable :logs="store.logs" />
    <div class="flex justify-between items-center mt-4 text-sm text-gray-500">
      <span>{{ store.total }} total entries</span>
      <div class="flex gap-2">
        <button @click="prevPage" :disabled="offset === 0" class="px-3 py-1 bg-dark-800 rounded disabled:opacity-50">Prev</button>
        <button @click="nextPage" :disabled="offset + 50 >= store.total" class="px-3 py-1 bg-dark-800 rounded disabled:opacity-50">Next</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useAuditStore } from '../stores/audit'
import RequestTable from '../components/RequestTable.vue'

const store = useAuditStore()
const offset = ref(0)
const filters = reactive({ policy_action: '', model: '' })

function load() {
  store.fetchLogs({ ...filters, offset: offset.value, limit: 50 })
}
function prevPage() { offset.value = Math.max(0, offset.value - 50); load() }
function nextPage() { offset.value += 50; load() }

onMounted(load)
</script>
