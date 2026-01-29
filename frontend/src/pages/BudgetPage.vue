<template>
  <div>
    <h2 class="text-2xl font-bold mb-6">Budget</h2>
    <div v-if="budget" class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <BudgetGauge label="Monthly Spend" :spent="budget.monthly_spent_usd" :limit="budget.monthly_limit_usd" type="currency" />
      <BudgetGauge label="Token Usage" :spent="budget.monthly_tokens_used" :limit="budget.monthly_token_limit" type="number" />
    </div>
    <p v-else class="text-gray-500">No budget configured.</p>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../api/client'
import BudgetGauge from '../components/BudgetGauge.vue'

const budget = ref<any>(null)

onMounted(async () => {
  try {
    const token = localStorage.getItem('token')
    if (token) {
      const payload = JSON.parse(atob(token.split('.')[1]))
      const { data } = await api.get(`/budgets/${payload.user_id}`)
      budget.value = data
    }
  } catch { /* no budget */ }
})
</script>
