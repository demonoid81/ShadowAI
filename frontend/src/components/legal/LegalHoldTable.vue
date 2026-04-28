<template>
  <section class="console-card">
    <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
      <div>
        <div class="section-kicker">{{ $t('legalHolds.tableKicker') }}</div>
        <h3 class="section-title">{{ $t('legalHolds.tableTitle') }}</h3>
      </div>
      <div class="flex flex-wrap gap-2">
        <button type="button" class="rounded-xl border border-emerald-300/20 px-3 py-2 text-xs font-semibold text-emerald-100 hover:bg-emerald-400/10" @click="$emit('bulk-approve')">
          {{ $t('legalHolds.bulkApprove') }}
        </button>
        <button type="button" class="rounded-xl border border-red-300/20 px-3 py-2 text-xs font-semibold text-red-100 hover:bg-red-400/10" @click="$emit('bulk-reject')">
          {{ $t('legalHolds.bulkReject') }}
        </button>
      </div>
    </div>

    <div v-if="loading" class="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">{{ $t('common.loading') }}</div>
    <div v-else-if="holds.length === 0" class="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">{{ $t('legalHolds.empty') }}</div>
    <div v-else class="mt-5 overflow-hidden rounded-2xl border border-white/10">
      <table class="w-full text-sm">
        <thead class="bg-white/[0.03] text-left text-xs uppercase tracking-[0.2em] text-slate-500">
          <tr>
            <th class="px-4 py-3"></th>
            <th class="px-4 py-3">{{ $t('legalHolds.caseRef') }}</th>
            <th class="px-4 py-3">{{ $t('legalHolds.status') }}</th>
            <th class="px-4 py-3">{{ $t('legalHolds.targetUser') }}</th>
            <th class="px-4 py-3">{{ $t('legalHolds.scope') }}</th>
            <th class="px-4 py-3">{{ $t('legalHolds.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="hold in holds" :key="hold.id" class="border-t border-white/10 align-top">
            <td class="px-4 py-3">
              <input :checked="selectedIds.has(hold.id)" type="checkbox" class="h-4 w-4 accent-cyan-300" @change="$emit('toggle-select', hold.id)" />
            </td>
            <td class="px-4 py-3">
              <div class="font-semibold text-white">{{ hold.case_ref }}</div>
              <div class="mt-1 max-w-sm truncate text-xs text-slate-500">{{ hold.reason }}</div>
            </td>
            <td class="px-4 py-3">
              <span class="rounded-full px-3 py-1 text-xs font-semibold" :class="statusClass(hold.status)">{{ hold.status }}</span>
            </td>
            <td class="px-4 py-3 font-mono text-xs text-slate-400">{{ hold.target_user_id }}</td>
            <td class="px-4 py-3 text-xs text-slate-400">
              <div>{{ hold.scope_type }}</div>
              <div v-if="hold.selector_hash" class="mt-1 font-mono text-slate-600">{{ hold.selector_hash }}</div>
            </td>
            <td class="px-4 py-3">
              <div class="flex flex-wrap gap-2">
                <button
                  v-for="action in actionsFor(hold.status)"
                  :key="action"
                  type="button"
                  class="rounded-lg border border-white/10 px-2 py-1 text-xs font-semibold text-slate-200 hover:bg-white/[0.05]"
                  @click="$emit('transition', hold.id, action)"
                >
                  {{ $t(`legalHolds.actionLabels.${action}`) }}
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup lang="ts">
import type { LegalHold } from '../../api/legal'
import { legalHoldActions, type LegalHoldAction } from '../../utils/legalHoldUi'

defineProps<{
  holds: LegalHold[]
  selectedIds: Set<string>
  loading: boolean
}>()

defineEmits<{
  'toggle-select': [id: string]
  transition: [id: string, action: LegalHoldAction]
  'bulk-approve': []
  'bulk-reject': []
}>()

function actionsFor(status: string) {
  return legalHoldActions(status)
}

function statusClass(status: string) {
  if (status === 'active') return 'bg-emerald-300/10 text-emerald-200'
  if (status === 'pending') return 'bg-amber-300/10 text-amber-200'
  if (status === 'release_pending') return 'bg-sky-300/10 text-sky-200'
  return 'bg-slate-300/10 text-slate-300'
}
</script>
