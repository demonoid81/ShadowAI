<template>
  <div class="bg-dark-900 border border-dark-700 rounded-xl p-6">
    <h3 class="text-lg font-semibold mb-4">{{ editing ? 'Edit Rule' : 'New Rule' }}</h3>
    <form @submit.prevent="$emit('submit', form)" class="space-y-4">
      <div>
        <label class="block text-sm text-gray-400 mb-1">Name</label>
        <input v-model="form.name" required class="w-full px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 focus:border-primary-500 focus:outline-none" />
      </div>
      <div>
        <label class="block text-sm text-gray-400 mb-1">Type</label>
        <select v-model="form.rule_type" class="w-full px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 focus:border-primary-500 focus:outline-none">
          <option value="pii_block">PII Block</option>
          <option value="pii_warn">PII Warn</option>
          <option value="keyword_block">Keyword Block</option>
          <option value="model_restrict">Model Restrict</option>
        </select>
      </div>
      <div>
        <label class="block text-sm text-gray-400 mb-1">Priority</label>
        <input v-model.number="form.priority" type="number" class="w-full px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 focus:border-primary-500 focus:outline-none" />
      </div>
      <div class="flex items-center gap-2">
        <input v-model="form.is_active" type="checkbox" class="rounded" />
        <label class="text-sm text-gray-400">Active</label>
      </div>
      <button type="submit" class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white text-sm transition-colors">
        {{ editing ? 'Update' : 'Create' }}
      </button>
    </form>
  </div>
</template>

<script setup lang="ts">
import { reactive } from 'vue'

const props = defineProps<{ editing?: boolean; initial?: any }>()
defineEmits(['submit'])

const form = reactive({
  name: props.initial?.name || '',
  rule_type: props.initial?.rule_type || 'pii_block',
  config: props.initial?.config || {},
  is_active: props.initial?.is_active ?? true,
  priority: props.initial?.priority || 0
})
</script>
