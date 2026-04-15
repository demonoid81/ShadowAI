<template>
  <div>
    <h2 class="text-2xl font-bold mb-6">{{ $t('budget.title') }}</h2>
    <div v-if="budget" class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <BudgetGauge :label="t('budget.monthlySpend')" :spent="budget.monthly_spent_usd" :limit="budget.monthly_limit_usd" type="currency" />
      <BudgetGauge :label="t('budget.tokenUsage')" :spent="budget.monthly_tokens_used" :limit="budget.monthly_token_limit" type="number" />
    </div>
    <p v-else class="text-gray-500">{{ $t('budget.noBudget') }}</p>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '../api/client'
import BudgetGauge from '../components/BudgetGauge.vue'

const { t } = useI18n()
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
