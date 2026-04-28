<template>
  <section class="console-card">
    <div class="section-kicker">{{ $t('legalHolds.createKicker') }}</div>
    <h3 class="section-title">{{ $t('legalHolds.createTitle') }}</h3>
    <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t('legalHolds.createBody') }}</p>

    <form class="mt-5 grid gap-3 md:grid-cols-2" @submit.prevent="$emit('create')">
      <input :value="draft.target_user_id" required class="tenant-input" :placeholder="$t('legalHolds.targetUser')" @input="patch('target_user_id', ($event.target as HTMLInputElement).value)" />
      <input :value="draft.case_ref" required class="tenant-input" :placeholder="$t('legalHolds.caseRef')" @input="patch('case_ref', ($event.target as HTMLInputElement).value)" />
      <input :value="draft.reason" required class="tenant-input md:col-span-2" :placeholder="$t('legalHolds.reason')" @input="patch('reason', ($event.target as HTMLInputElement).value)" />
      <select :value="draft.scope_type" class="tenant-input" @change="patch('scope_type', ($event.target as HTMLSelectElement).value)">
        <option value="whole_user">{{ $t('legalHolds.scopes.wholeUser') }}</option>
        <option value="date_range">{{ $t('legalHolds.scopes.dateRange') }}</option>
        <option value="query_scope">{{ $t('legalHolds.scopes.queryScope') }}</option>
      </select>
      <div v-if="draft.scope_type === 'date_range'" class="grid gap-3 md:grid-cols-2 md:col-span-2">
        <input :value="draft.scope_date_from" type="datetime-local" class="tenant-input" @input="patch('scope_date_from', ($event.target as HTMLInputElement).value)" />
        <input :value="draft.scope_date_to" type="datetime-local" class="tenant-input" @input="patch('scope_date_to', ($event.target as HTMLInputElement).value)" />
      </div>
      <textarea
        v-if="draft.scope_type === 'query_scope'"
        :value="scopeQueryText"
        rows="5"
        class="tenant-input font-mono md:col-span-2"
        :placeholder="$t('legalHolds.scopeQueryPlaceholder')"
        @input="$emit('update:scopeQueryText', ($event.target as HTMLTextAreaElement).value)"
      />
      <div class="flex flex-wrap gap-3 md:col-span-2">
        <button type="submit" :disabled="saving" class="rounded-xl bg-cyan-300 px-4 py-2 text-sm font-bold text-slate-950 disabled:opacity-50">
          {{ saving ? $t('common.saving') : $t('legalHolds.create') }}
        </button>
        <button v-if="draft.scope_type === 'query_scope'" type="button" :disabled="saving" class="rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-slate-200 hover:bg-white/[0.04]" @click="$emit('preview')">
          {{ $t('legalHolds.preview') }}
        </button>
      </div>
    </form>

    <div v-if="preview" class="mt-5 rounded-2xl border border-emerald-300/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">
      {{ $t('legalHolds.previewRows', { count: preview.matched_rows }) }}
      <div class="mt-2 font-mono text-xs text-emerald-100/80">{{ preview.selector_hash }}</div>
    </div>
  </section>
</template>

<script setup lang="ts">
import type { LegalHoldCreateInput, LegalHoldPreview } from '../../api/legal'

const props = defineProps<{
  draft: LegalHoldCreateInput
  scopeQueryText: string
  preview: LegalHoldPreview | null
  saving: boolean
}>()

const emit = defineEmits<{
  'update:draft': [draft: LegalHoldCreateInput]
  'update:scopeQueryText': [value: string]
  create: []
  preview: []
}>()

function patch(key: keyof LegalHoldCreateInput, value: string) {
  emit('update:draft', { ...props.draft, [key]: value })
}
</script>
