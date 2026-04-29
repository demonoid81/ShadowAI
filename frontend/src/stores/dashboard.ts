import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../api/client'

export const useDashboardStore = defineStore('dashboard', () => {
  const stats = ref<any>(null)
  const usage = ref<any[]>([])
  const topUsers = ref<any[]>([])
  const statsLoading = ref(false)
  const usageLoading = ref(false)
  const topUsersLoading = ref(false)
  const statsError = ref('')
  const usageError = ref('')
  const topUsersError = ref('')

  async function fetchStats() {
    statsLoading.value = true
    statsError.value = ''
    try {
      const { data } = await api.get('/dashboard/stats')
      stats.value = data
    } catch {
      stats.value = null
      statsError.value = 'dashboard.errors.stats'
    } finally {
      statsLoading.value = false
    }
  }

  async function fetchUsage() {
    usageLoading.value = true
    usageError.value = ''
    try {
      const { data } = await api.get('/dashboard/usage')
      usage.value = Array.isArray(data) ? data : []
    } catch {
      usage.value = []
      usageError.value = 'dashboard.errors.usage'
    } finally {
      usageLoading.value = false
    }
  }

  async function fetchTopUsers() {
    topUsersLoading.value = true
    topUsersError.value = ''
    try {
      const { data } = await api.get('/dashboard/top-users')
      topUsers.value = Array.isArray(data) ? data : []
    } catch {
      topUsers.value = []
      topUsersError.value = 'dashboard.errors.topUsers'
    } finally {
      topUsersLoading.value = false
    }
  }

  return {
    stats,
    usage,
    topUsers,
    statsLoading,
    usageLoading,
    topUsersLoading,
    statsError,
    usageError,
    topUsersError,
    fetchStats,
    fetchUsage,
    fetchTopUsers
  }
})
