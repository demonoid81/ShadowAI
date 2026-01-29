<template>
  <div>
    <div class="flex justify-between items-center mb-6">
      <h2 class="text-2xl font-bold">Policies</h2>
      <button @click="showForm = !showForm" class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-sm transition-colors">
        {{ showForm ? 'Cancel' : 'New Rule' }}
      </button>
    </div>
    <PolicyRuleForm v-if="showForm" @submit="createRule" class="mb-6" />
    <div class="space-y-3">
      <div v-for="rule in rules" :key="rule.id" class="bg-dark-900 border border-dark-700 rounded-xl p-4 flex justify-between items-center">
        <div>
          <h4 class="font-medium">{{ rule.name }}</h4>
          <p class="text-sm text-gray-500">{{ rule.rule_type }} · Priority: {{ rule.priority }}</p>
        </div>
        <div class="flex gap-2 items-center">
          <span :class="rule.is_active ? 'text-green-400' : 'text-gray-600'" class="text-sm">{{ rule.is_active ? 'Active' : 'Inactive' }}</span>
          <button @click="deleteRule(rule.id)" class="px-3 py-1 text-red-400 hover:bg-red-900/30 rounded text-sm transition-colors">Delete</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../api/client'
import PolicyRuleForm from '../components/PolicyRuleForm.vue'

const rules = ref<any[]>([])
const showForm = ref(false)

async function fetchRules() {
  const { data } = await api.get('/policies')
  rules.value = data
}

async function createRule(form: any) {
  await api.post('/policies', form)
  showForm.value = false
  fetchRules()
}

async function deleteRule(id: string) {
  await api.delete(`/policies/${id}`)
  fetchRules()
}

onMounted(fetchRules)
</script>
