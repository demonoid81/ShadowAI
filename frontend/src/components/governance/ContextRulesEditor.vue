<template>
  <div class="space-y-4">
    <div v-for="(rule, index) in contextRules" :key="index" class="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
      <div class="mb-4 grid gap-3 md:grid-cols-[1fr_1fr_auto]">
        <input
          :value="rule.department"
          class="tenant-input"
          :placeholder="$t('policies.governance.departmentPlaceholder')"
          @input="patch(index, { department: ($event.target as HTMLInputElement).value })"
        />
        <input
          :value="rule.role"
          class="tenant-input"
          :placeholder="$t('policies.governance.roleWildcardPlaceholder')"
          @input="patch(index, { role: ($event.target as HTMLInputElement).value })"
        />
        <button type="button" class="rounded-xl border border-red-300/20 px-3 py-2 text-xs font-semibold text-red-100 hover:bg-red-400/10" @click="removeRule(index)">
          {{ $t('policies.governance.removeContextRule') }}
        </button>
      </div>

      <div class="mb-4">
        <div class="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('policies.governance.sensitivity') }}</div>
        <div class="flex flex-wrap gap-2">
          <label v-for="level in sensitivityLevels" :key="level" class="rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-300">
            <input
              type="checkbox"
              class="mr-2 accent-cyan-300"
              :checked="(rule.sensitivity ?? []).includes(level)"
              @change="toggleSensitivity(index, level)"
            />
            {{ level }}
          </label>
        </div>
        <p class="mt-2 text-xs text-slate-500">{{ $t('policies.governance.emptySensitivityAny') }}</p>
      </div>

      <ProviderRulesEditor :rules="rule.rules" @update:rules="patch(index, { rules: $event })" />
    </div>
    <button type="button" class="rounded-xl border border-cyan-300/20 px-3 py-2 text-xs font-semibold text-cyan-100 hover:bg-cyan-400/10" @click="addRule">
      {{ $t('policies.governance.addContextRule') }}
    </button>
  </div>
</template>

<script setup lang="ts">
import ProviderRulesEditor from './ProviderRulesEditor.vue'
import {
  emptyContextRule,
  sensitivityLevels,
  type ContextRuleDraft,
  type SensitivityLevel
} from '../../utils/governanceUi'

const props = defineProps<{ contextRules: ContextRuleDraft[] }>()
const emit = defineEmits<{ 'update:context-rules': [rules: ContextRuleDraft[]] }>()

function clone() {
  return props.contextRules.map(rule => ({
    department: rule.department,
    role: rule.role,
    sensitivity: [...(rule.sensitivity ?? [])],
    rules: rule.rules.map(providerRule => ({ provider: providerRule.provider, models: [...providerRule.models] }))
  }))
}

function patch(index: number, partial: Partial<ContextRuleDraft>) {
  const next = clone()
  next[index] = { ...next[index], ...partial }
  emit('update:context-rules', next)
}

function toggleSensitivity(index: number, level: SensitivityLevel) {
  const current = props.contextRules[index].sensitivity ?? []
  const nextSensitivity = current.includes(level) ? current.filter(item => item !== level) : [...current, level]
  patch(index, { sensitivity: nextSensitivity })
}

function addRule() {
  emit('update:context-rules', [...clone(), emptyContextRule()])
}

function removeRule(index: number) {
  emit('update:context-rules', clone().filter((_, i) => i !== index))
}
</script>
