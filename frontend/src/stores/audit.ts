import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../api/client'

export const useAuditStore = defineStore('audit', () => {
  const logs = ref<any[]>([])
  const total = ref(0)
  const loading = ref(false)

  async function fetchLogs(params: Record<string, any> = {}) {
    loading.value = true
    try {
      const { data } = await api.get('/audit/logs', { params })
      logs.value = data.data
      total.value = data.total
    } finally {
      loading.value = false
    }
  }

  return { logs, total, loading, fetchLogs }
})
