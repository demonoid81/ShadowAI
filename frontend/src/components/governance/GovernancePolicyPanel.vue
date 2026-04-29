<template>
  <section class="console-card">
    <div class="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
      <div>
        <div class="section-kicker">{{ $t('policies.governance.kicker') }}</div>
        <h3 class="section-title">{{ $t('policies.governance.title') }}</h3>
        <p class="mt-2 max-w-3xl text-sm leading-6 text-slate-400">{{ $t('policies.governance.body') }}</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button type="button" class="rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-slate-200 hover:bg-white/[0.04]" @click="$emit('reload')">
          {{ loading ? $t('common.loading') : $t('policies.governance.reload') }}
        </button>
        <button type="button" :disabled="saving" class="rounded-xl bg-cyan-300 px-4 py-2 text-sm font-bold text-slate-950 disabled:opacity-50" @click="$emit('save')">
          {{ saving ? $t('common.saving') : $t('policies.governance.save') }}
        </button>
      </div>
    </div>

    <div class="mt-5 grid gap-4 md:grid-cols-3">
      <div class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
        <div class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('policies.governance.configured') }}</div>
        <div class="mt-2 text-lg font-semibold text-white">{{ configured ? $t('common.yes') : $t('common.no') }}</div>
      </div>
      <div class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
        <div class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('policies.governance.currentMode') }}</div>
        <div class="mt-2 text-lg font-semibold text-cyan-100">{{ draft.mode }}</div>
      </div>
      <div class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
        <div class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('policies.governance.updatedAt') }}</div>
        <div class="mt-2 text-sm font-mono text-slate-300">{{ policy?.updated_at || '—' }}</div>
      </div>
    </div>

    <div v-if="warnings.length" class="mt-5 rounded-2xl border border-amber-200/20 bg-amber-200/10 p-4 text-sm text-amber-100">
      <div class="font-semibold">{{ $t('policies.governance.warningsTitle') }}</div>
      <ul class="mt-2 list-disc space-y-1 pl-5">
        <li v-for="warning in warnings" :key="warning">{{ $t(`policies.governance.warnings.${warning}`) }}</li>
      </ul>
    </div>

    <div class="mt-6 grid gap-4 md:grid-cols-[1fr_0.7fr]">
      <label class="block">
        <span class="mb-2 block text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('policies.governance.policyName') }}</span>
        <input :value="draft.name" class="tenant-input" @input="patch({ name: ($event.target as HTMLInputElement).value })" />
      </label>
      <label class="block">
        <span class="mb-2 block text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('policies.governance.mode') }}</span>
        <select :value="draft.mode" class="tenant-input" @change="patch({ mode: ($event.target as HTMLSelectElement).value as GovernanceMode })">
          <option v-for="mode in governanceModes" :key="mode" :value="mode">{{ mode }}</option>
        </select>
      </label>
    </div>

    <div class="mt-6">
      <ProviderRulesEditor
        v-if="draft.mode === 'allowlist_strict'"
        :rules="draft.rules"
        @update:rules="patch({ rules: $event })"
      />
      <RoleRulesEditor
        v-else-if="draft.mode === 'role_based'"
        :role-rules="draft.role_rules"
        @update:role-rules="patch({ role_rules: $event })"
      />
      <ContextRulesEditor
        v-else-if="draft.mode === 'context_scoped'"
        :context-rules="draft.context_rules"
        @update:context-rules="patch({ context_rules: $event })"
      />
      <div v-else class="rounded-2xl border border-white/10 bg-white/[0.03] p-5 text-sm text-slate-400">
        {{ $t('policies.governance.disabledBody') }}
      </div>
    </div>

    <div class="mt-6 rounded-3xl border border-white/10 bg-black/20 p-4">
      <button type="button" class="text-sm font-semibold text-cyan-100" @click="$emit('update:show-json', !showJson)">
        {{ showJson ? $t('policies.governance.hideJson') : $t('policies.governance.showJson') }}
      </button>
      <div v-if="showJson" class="mt-4 grid gap-4 xl:grid-cols-2">
        <div>
          <div class="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('policies.governance.jsonPreview') }}</div>
          <pre class="max-h-96 overflow-auto rounded-2xl bg-black/40 p-4 text-xs text-slate-300"><code>{{ jsonPreview }}</code></pre>
        </div>
        <div>
          <div class="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('policies.governance.jsonFallback') }}</div>
          <textarea
            :value="jsonDraft"
            rows="14"
            class="tenant-input font-mono text-xs"
            @input="$emit('update:json-draft', ($event.target as HTMLTextAreaElement).value)"
          />
          <button type="button" class="mt-3 rounded-xl border border-cyan-300/20 px-3 py-2 text-xs font-semibold text-cyan-100 hover:bg-cyan-400/10" @click="$emit('apply-json')">
            {{ $t('policies.governance.applyJson') }}
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import ContextRulesEditor from './ContextRulesEditor.vue'
import ProviderRulesEditor from './ProviderRulesEditor.vue'
import RoleRulesEditor from './RoleRulesEditor.vue'
import { governanceModes, type GovernanceMode, type GovernancePolicyDraft } from '../../utils/governanceUi'
import type { GovernancePolicy } from '../../api/governance'

const props = defineProps<{
  draft: GovernancePolicyDraft
  policy: GovernancePolicy | null
  configured: boolean
  loading: boolean
  saving: boolean
  warnings: string[]
  jsonPreview: string
  jsonDraft: string
  showJson: boolean
}>()

const emit = defineEmits<{
  'update:draft': [draft: GovernancePolicyDraft]
  'update:json-draft': [value: string]
  'update:show-json': [value: boolean]
  save: []
  reload: []
  'apply-json': []
}>()

function patch(partial: Partial<GovernancePolicyDraft>) {
  emit('update:draft', { ...props.draft, ...partial })
}
</script>
