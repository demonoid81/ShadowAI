import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../api/client'

export const useDashboardStore = defineStore('dashboard', () => {
  const stats = ref<any>(null)
  const usage = ref<any[]>([])
  const topUsers = ref<any[]>([])

  async function fetchStats() {
    const { data } = await api.get('/dashboard/stats')
    stats.value = data
  }

  async function fetchUsage() {
    const { data } = await api.get('/dashboard/usage')
    usage.value = data
  }

  async function fetchTopUsers() {
    const { data } = await api.get('/dashboard/top-users')
    topUsers.value = data
  }

  return { stats, usage, topUsers, fetchStats, fetchUsage, fetchTopUsers }
})
