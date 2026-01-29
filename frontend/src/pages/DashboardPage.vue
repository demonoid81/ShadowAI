<template>
  <div>
    <h2 class="text-2xl font-bold mb-6">Dashboard</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8" v-if="store.stats">
      <StatsCard label="Total Requests" :value="store.stats.total_requests" format="number" />
      <StatsCard label="Blocked Requests" :value="store.stats.blocked_requests" format="number" color="text-red-400" />
      <StatsCard label="Total Cost" :value="store.stats.total_cost" format="currency" color="text-green-400" />
      <StatsCard label="Active Users" :value="store.stats.active_users" format="number" color="text-primary-400" />
    </div>
    <div class="mb-8">
      <UsageChart :data="store.usage" />
    </div>
    <div class="bg-dark-900 border border-dark-700 rounded-xl p-6">
      <h3 class="text-lg font-semibold mb-4">Top Users by Cost</h3>
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left text-gray-500 border-b border-dark-700">
            <th class="px-4 py-2">Email</th>
            <th class="px-4 py-2">Requests</th>
            <th class="px-4 py-2">Cost</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in store.topUsers" :key="u.user_id" class="border-b border-dark-800">
            <td class="px-4 py-2">{{ u.email }}</td>
            <td class="px-4 py-2 text-gray-400">{{ u.requests }}</td>
            <td class="px-4 py-2 text-green-400">${{ u.cost?.toFixed(4) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useDashboardStore } from '../stores/dashboard'
import StatsCard from '../components/StatsCard.vue'
import UsageChart from '../components/UsageChart.vue'

const store = useDashboardStore()

onMounted(() => {
  store.fetchStats()
  store.fetchUsage()
  store.fetchTopUsers()
})
</script>
