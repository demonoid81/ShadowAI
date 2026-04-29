<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 max-w-5xl">
        <div class="mb-5 flex flex-wrap gap-2">
          <span class="tag-chip">provider/model</span>
          <span class="tag-chip">role_based</span>
          <span class="tag-chip">context_scoped</span>
        </div>
        <h2 class="text-4xl font-semibold tracking-tight text-white sm:text-5xl">{{ $t('policies.governance.heroTitle') }}</h2>
        <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">{{ $t('policies.governance.heroSubtitle') }}</p>
      </div>
    </section>

    <div v-if="governanceError" class="rounded-3xl border border-red-300/20 bg-red-400/10 p-4 text-sm text-red-100">{{ governanceError }}</div>
    <div v-if="governanceSuccess" class="rounded-3xl border border-emerald-300/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">{{ governanceSuccess }}</div>

    <GovernancePolicyPanel
      :draft="draft"
      :policy="policy"
      :configured="configured"
      :loading="loading"
      :saving="saving"
      :warnings="warnings"
      :json-preview="jsonPreview"
      :json-draft="jsonDraft"
      :show-json="showJson"
      @update:draft="Object.assign(draft, $event)"
      @update:json-draft="jsonDraft = $event"
      @update:show-json="showJson = $event"
      @save="savePolicy"
      @reload="loadPolicy"
      @apply-json="applyJSONDraft"
    />

    <section class="console-card">
      <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <div class="section-kicker">{{ $t('policies.legacyKicker') }}</div>
          <h3 class="section-title">{{ $t('policies.legacyTitle') }}</h3>
          <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t('policies.legacyBody') }}</p>
        </div>
        <button type="button" class="rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-slate-200 hover:bg-white/[0.04]" @click="showForm = !showForm">
          {{ showForm ? $t('policies.cancel') : $t('policies.newRule') }}
        </button>
      </div>

      <PolicyRuleForm v-if="showForm" class="mt-5" @submit="createRule" />

      <div v-if="legacyError" class="mt-5 rounded-2xl border border-red-300/20 bg-red-400/10 p-4 text-sm text-red-100">{{ legacyError }}</div>
      <div v-if="rules.length === 0" class="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-500">
        {{ $t('policies.noLegacyRules') }}
      </div>
      <div v-else class="mt-5 space-y-3">
        <div v-for="rule in rules" :key="rule.id" class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
          <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <h4 class="font-medium text-white">{{ rule.name }}</h4>
              <p class="text-sm text-slate-500">{{ rule.rule_type }} · {{ $t('policies.priority') }}: {{ rule.priority }}</p>
            </div>
            <div class="flex items-center gap-2">
              <span :class="rule.is_active ? 'text-emerald-300' : 'text-slate-600'" class="text-sm">{{ rule.is_active ? $t('policies.active') : $t('policies.inactive') }}</span>
              <button type="button" class="rounded-xl border border-red-300/20 px-3 py-1 text-sm text-red-200 hover:bg-red-400/10" @click="deleteRule(rule.id)">
                {{ $t('policies.delete') }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '../api/client'
import GovernancePolicyPanel from '../components/governance/GovernancePolicyPanel.vue'
import PolicyRuleForm from '../components/PolicyRuleForm.vue'
import { useGovernancePolicy } from '../composables/useGovernancePolicy'

const { t } = useI18n()
const rules = ref<any[]>([])
const showForm = ref(false)
const legacyError = ref('')

const {
  policy, configured, loading, saving, error: governanceError, success: governanceSuccess,
  draft, warnings, jsonPreview, jsonDraft, showJson,
  loadPolicy, savePolicy, applyJSONDraft
} = useGovernancePolicy()

async function fetchRules() {
  legacyError.value = ''
  try {
    const { data } = await api.get('/policies')
    rules.value = data
  } catch (err) {
    const anyErr = err as { response?: { data?: { error?: string } } }
    legacyError.value = anyErr.response?.data?.error || t('policies.legacyLoadFailed')
  }
}

async function createRule(form: any) {
  try {
    await api.post('/policies', form)
    showForm.value = false
    await fetchRules()
  } catch (err) {
    const anyErr = err as { response?: { data?: { error?: string } } }
    legacyError.value = anyErr.response?.data?.error || t('policies.legacySaveFailed')
  }
}

async function deleteRule(id: string) {
  try {
    await api.delete(`/policies/${id}`)
    await fetchRules()
  } catch (err) {
    const anyErr = err as { response?: { data?: { error?: string } } }
    legacyError.value = anyErr.response?.data?.error || t('policies.legacyDeleteFailed')
  }
}

onMounted(() => {
  loadPolicy()
  fetchRules()
})
</script>
