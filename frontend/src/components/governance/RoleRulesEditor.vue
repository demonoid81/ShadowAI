<template>
  <div class="space-y-4">
    <div v-for="(rule, index) in roleRules" :key="index" class="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
      <div class="mb-3 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <input
          :value="rule.role"
          class="tenant-input md:max-w-xs"
          :placeholder="$t('policies.governance.rolePlaceholder')"
          @input="updateRole(index, ($event.target as HTMLInputElement).value)"
        />
        <button type="button" class="rounded-xl border border-red-300/20 px-3 py-2 text-xs font-semibold text-red-100 hover:bg-red-400/10" @click="removeRule(index)">
          {{ $t('policies.governance.removeRoleRule') }}
        </button>
      </div>
      <ProviderRulesEditor :rules="rule.rules" @update:rules="updateRules(index, $event)" />
    </div>
    <button type="button" class="rounded-xl border border-cyan-300/20 px-3 py-2 text-xs font-semibold text-cyan-100 hover:bg-cyan-400/10" @click="addRule">
      {{ $t('policies.governance.addRoleRule') }}
    </button>
  </div>
</template>

<script setup lang="ts">
import ProviderRulesEditor from './ProviderRulesEditor.vue'
import { emptyRoleRule, type ProviderRuleDraft, type RoleRuleDraft } from '../../utils/governanceUi'

const props = defineProps<{ roleRules: RoleRuleDraft[] }>()
const emit = defineEmits<{ 'update:role-rules': [rules: RoleRuleDraft[]] }>()

function clone() {
  return props.roleRules.map(rule => ({
    role: rule.role,
    rules: rule.rules.map(providerRule => ({ provider: providerRule.provider, models: [...providerRule.models] }))
  }))
}

function updateRole(index: number, role: string) {
  const next = clone()
  next[index].role = role
  emit('update:role-rules', next)
}

function updateRules(index: number, rules: ProviderRuleDraft[]) {
  const next = clone()
  next[index].rules = rules
  emit('update:role-rules', next)
}

function addRule() {
  emit('update:role-rules', [...clone(), emptyRoleRule()])
}

function removeRule(index: number) {
  emit('update:role-rules', clone().filter((_, i) => i !== index))
}
</script>
