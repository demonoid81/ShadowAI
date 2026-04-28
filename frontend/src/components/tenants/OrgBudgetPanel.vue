<template>
  <section class="console-card">
    <div class="section-kicker">{{ $t('tenants.budget.kicker') }}</div>
    <h3 class="section-title">{{ $t('tenants.budget.title') }}</h3>
    <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t('tenants.budget.body') }}</p>

    <div v-if="loading" class="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
      {{ $t('common.loading') }}
    </div>

    <form v-else class="mt-5 grid gap-4 md:grid-cols-[0.9fr_0.8fr_auto]" @submit.prevent="$emit('save-budget')">
      <label class="tenant-label">
        {{ $t('tenants.budget.limit') }}
        <input
          :value="limitDollars"
          type="number"
          min="0"
          step="0.01"
          class="tenant-input mt-2"
          @input="$emit('update:limitDollars', ($event.target as HTMLInputElement).value)"
        />
      </label>
      <label class="tenant-label">
        {{ $t('tenants.budget.mode') }}
        <select
          :value="mode"
          class="tenant-input mt-2"
          @change="$emit('update:mode', ($event.target as HTMLSelectElement).value as 'disabled' | 'observe' | 'enforce')"
        >
          <option value="disabled">{{ $t('tenants.budget.modes.disabled') }}</option>
          <option value="observe">{{ $t('tenants.budget.modes.observe') }}</option>
          <option value="enforce">{{ $t('tenants.budget.modes.enforce') }}</option>
        </select>
      </label>
      <div class="flex items-end">
        <button type="submit" :disabled="saving" class="w-full rounded-xl bg-cyan-300 px-4 py-2 text-sm font-bold text-slate-950 disabled:opacity-50">
          {{ saving ? $t('common.saving') : $t('tenants.budget.save') }}
        </button>
      </div>
    </form>

    <div v-if="status" class="mt-5 grid gap-3 sm:grid-cols-3">
      <div class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
        <div class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('tenants.budget.spent') }}</div>
        <div class="mt-2 text-2xl font-semibold text-white">${{ centsToDollars(status.usage.spent_cents) }}</div>
      </div>
      <div class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
        <div class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('tenants.budget.remaining') }}</div>
        <div class="mt-2 text-2xl font-semibold" :class="status.remaining_cents < 0 ? 'text-red-200' : 'text-emerald-200'">
          ${{ centsToDollars(status.remaining_cents) }}
        </div>
      </div>
      <div class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
        <div class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('tenants.budget.period') }}</div>
        <div class="mt-2 text-sm text-slate-300">{{ formatDate(status.usage.period_start) }}</div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import type { OrgBudgetStatus } from '../../api/tenants'
import { centsToDollars } from '../../utils/tenantUi'

defineProps<{
  status: OrgBudgetStatus | null
  limitDollars: string
  mode: 'disabled' | 'observe' | 'enforce'
  loading: boolean
  saving: boolean
}>()

defineEmits<{
  'update:limitDollars': [limitDollars: string]
  'update:mode': [mode: 'disabled' | 'observe' | 'enforce']
  'save-budget': []
}>()

function formatDate(value: string) {
  return value ? new Date(value).toLocaleDateString() : '—'
}
</script>
