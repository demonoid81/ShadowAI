<template>
  <div class="space-y-3">
    <div v-for="(rule, index) in rules" :key="index" class="rounded-2xl border border-white/10 bg-white/[0.03] p-3">
      <div class="grid gap-3 md:grid-cols-[0.6fr_1fr_auto]">
        <input
          :value="rule.provider"
          class="tenant-input"
          :placeholder="$t('policies.governance.provider')"
          @input="updateProvider(index, ($event.target as HTMLInputElement).value)"
        />
        <input
          :value="joinModels(rule.models)"
          class="tenant-input"
          :placeholder="$t('policies.governance.modelsPlaceholder')"
          @input="updateModels(index, ($event.target as HTMLInputElement).value)"
        />
        <button type="button" class="rounded-xl border border-red-300/20 px-3 py-2 text-xs font-semibold text-red-100 hover:bg-red-400/10" @click="removeRule(index)">
          {{ $t('policies.governance.remove') }}
        </button>
      </div>
    </div>
    <button type="button" class="rounded-xl border border-cyan-300/20 px-3 py-2 text-xs font-semibold text-cyan-100 hover:bg-cyan-400/10" @click="addRule">
      {{ $t('policies.governance.addProviderRule') }}
    </button>
  </div>
</template>

<script setup lang="ts">
import { emptyProviderRule, joinModels, splitModels, type ProviderRuleDraft } from '../../utils/governanceUi'

const props = defineProps<{ rules: ProviderRuleDraft[] }>()
const emit = defineEmits<{ 'update:rules': [rules: ProviderRuleDraft[]] }>()

function nextRules() {
  return props.rules.map(rule => ({ provider: rule.provider, models: [...rule.models] }))
}

function updateProvider(index: number, provider: string) {
  const next = nextRules()
  next[index].provider = provider
  emit('update:rules', next)
}

function updateModels(index: number, value: string) {
  const next = nextRules()
  next[index].models = splitModels(value)
  emit('update:rules', next)
}

function addRule() {
  emit('update:rules', [...nextRules(), emptyProviderRule()])
}

function removeRule(index: number) {
  emit('update:rules', nextRules().filter((_, i) => i !== index))
}
</script>
