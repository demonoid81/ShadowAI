<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 max-w-5xl">
        <div class="mb-5 flex flex-wrap gap-2">
          <span class="tag-chip">4-eyes</span>
          <span class="tag-chip">DSAR block</span>
          <span class="tag-chip">SLA</span>
        </div>
        <h2 class="text-4xl font-semibold tracking-tight text-white sm:text-5xl">{{ $t('legalHolds.title') }}</h2>
        <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">{{ $t('legalHolds.subtitle') }}</p>
      </div>
    </section>

    <div v-if="error" class="rounded-3xl border border-red-300/20 bg-red-400/10 p-4 text-sm text-red-100">{{ error }}</div>
    <div v-if="success" class="rounded-3xl border border-emerald-300/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">{{ success }}</div>

    <section class="grid gap-4 md:grid-cols-4">
      <article v-for="status in ['pending', 'active', 'release_pending', 'released']" :key="status" class="posture-card">
        <div class="text-xs uppercase tracking-[0.22em] text-slate-500">{{ status }}</div>
        <div class="mt-3 text-3xl font-semibold text-white">{{ statusCounts[status] ?? 0 }}</div>
      </article>
    </section>

    <section class="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
      <LegalHoldCreatePanel
        :draft="draft"
        :scope-query-text="scopeQueryText"
        :preview="preview"
        :saving="saving"
        @update:draft="Object.assign(draft, $event)"
        @update:scope-query-text="scopeQueryText = $event"
        @create="createHold"
        @preview="previewScope"
      />

      <section class="console-card">
        <div class="section-kicker">{{ $t('legalHolds.slaKicker') }}</div>
        <h3 class="section-title">{{ $t('legalHolds.slaTitle') }}</h3>
        <div class="mt-5 flex flex-wrap gap-3">
          <input v-model.number="slaThresholdHours" type="number" min="1" class="tenant-input max-w-40" />
          <button type="button" class="rounded-xl bg-cyan-300 px-4 py-2 text-sm font-bold text-slate-950" @click="loadPendingSLA">
            {{ $t('legalHolds.loadSla') }}
          </button>
        </div>
        <div v-if="pendingSLA" class="mt-5 rounded-2xl border border-amber-200/20 bg-amber-200/10 p-4 text-sm text-amber-100">
          {{ $t('legalHolds.slaResult', { count: pendingSLA.count, hours: pendingSLA.threshold_hours }) }}
        </div>
      </section>
    </section>

    <LegalHoldTable
      :holds="holds"
      :selected-ids="selectedIds"
      :loading="loading"
      @toggle-select="toggleSelect"
      @transition="transition"
      @bulk-approve="bulkApprove"
      @bulk-reject="bulkReject"
    />

    <section v-if="bulkResult" class="console-card">
      <div class="section-kicker">{{ $t('legalHolds.bulkResultKicker') }}</div>
      <h3 class="section-title">{{ $t('legalHolds.bulkResultTitle') }}</h3>
      <p class="mt-2 text-sm text-slate-400">
        {{ $t('legalHolds.messages.bulkDone', { success: bulkResult.success_count, failures: bulkResult.failure_count }) }}
      </p>
      <div class="mt-5 overflow-hidden rounded-2xl border border-white/10">
        <table class="w-full text-sm">
          <thead class="bg-white/[0.03] text-left text-xs uppercase tracking-[0.2em] text-slate-500">
            <tr>
              <th class="px-4 py-3">ID</th>
              <th class="px-4 py-3">{{ $t('legalHolds.status') }}</th>
              <th class="px-4 py-3">{{ $t('common.error') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in bulkResult.results" :key="item.id" class="border-t border-white/10">
              <td class="px-4 py-3 font-mono text-xs text-slate-400">{{ item.id }}</td>
              <td class="px-4 py-3" :class="item.success ? 'text-emerald-300' : 'text-red-300'">
                {{ item.status || (item.success ? $t('common.success') : $t('common.error')) }}
              </td>
              <td class="px-4 py-3 text-xs text-slate-500">{{ item.error || '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import LegalHoldCreatePanel from '../components/legal/LegalHoldCreatePanel.vue'
import LegalHoldTable from '../components/legal/LegalHoldTable.vue'
import { useLegalHolds } from '../composables/useLegalHolds'

const {
  holds, selectedIds, preview, pendingSLA, bulkResult, error, success, loading, saving,
  slaThresholdHours, scopeQueryText, draft, statusCounts,
  loadHolds, createHold, previewScope, transition, toggleSelect, bulkApprove, bulkReject, loadPendingSLA
} = useLegalHolds()

onMounted(() => {
  loadHolds()
  loadPendingSLA()
})
</script>
