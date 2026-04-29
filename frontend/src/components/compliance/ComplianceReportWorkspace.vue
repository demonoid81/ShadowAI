<template>
  <section class="console-card">
    <div class="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
      <div>
        <div class="section-kicker">{{ $t('compliance.workspace.kicker') }}</div>
        <h3 class="section-title">{{ $t('compliance.workspace.title') }}</h3>
        <p class="mt-2 max-w-3xl text-sm leading-6 text-slate-400">{{ $t('compliance.workspace.body') }}</p>
      </div>
      <label class="inline-flex cursor-pointer items-center rounded-xl bg-cyan-300 px-4 py-2 text-sm font-bold text-slate-950">
        {{ $t('compliance.workspace.upload') }}
        <input type="file" accept="application/json,.json" class="hidden" @change="onFile" />
      </label>
    </div>

    <div class="mt-5 rounded-2xl border border-amber-200/20 bg-amber-200/10 p-4 text-sm text-amber-100">
      {{ $t('compliance.workspace.localOnly') }}
    </div>

    <div v-if="error" class="mt-5 rounded-2xl border border-red-300/20 bg-red-400/10 p-4 text-sm text-red-100">{{ error }}</div>

    <template v-if="summary">
      <div class="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <article v-for="card in cards" :key="card.label" class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
          <div class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ card.label }}</div>
          <div class="mt-2 text-2xl font-semibold" :class="card.className">{{ card.value }}</div>
        </article>
      </div>

      <div class="mt-6 grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
        <div class="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
          <div class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('compliance.workspace.reportMeta') }}</div>
          <dl class="mt-4 space-y-3 text-sm">
            <div class="flex justify-between gap-4">
              <dt class="text-slate-500">{{ $t('compliance.workspace.file') }}</dt>
              <dd class="font-mono text-slate-200">{{ fileName || '—' }}</dd>
            </div>
            <div class="flex justify-between gap-4">
              <dt class="text-slate-500">{{ $t('compliance.workspace.reportTitle') }}</dt>
              <dd class="text-right text-slate-200">{{ summary.title }}</dd>
            </div>
            <div class="flex justify-between gap-4">
              <dt class="text-slate-500">{{ $t('compliance.workspace.reportType') }}</dt>
              <dd class="text-slate-200">{{ summary.type }}</dd>
            </div>
            <div class="flex justify-between gap-4">
              <dt class="text-slate-500">{{ $t('compliance.workspace.generatedAt') }}</dt>
              <dd class="font-mono text-slate-200">{{ summary.generatedAt || '—' }}</dd>
            </div>
            <div class="flex justify-between gap-4">
              <dt class="text-slate-500">{{ $t('compliance.workspace.period') }}</dt>
              <dd class="font-mono text-slate-200">{{ summary.period || '—' }}</dd>
            </div>
          </dl>
        </div>

        <div class="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
          <div class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('compliance.workspace.findings') }}</div>
          <div v-if="summary.findings.length === 0" class="mt-4 rounded-2xl border border-emerald-300/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">
            {{ $t('compliance.workspace.noFindings') }}
          </div>
          <div v-else class="mt-4 space-y-3">
            <div v-for="finding in summary.findings" :key="`${finding.code}-${finding.description}`" class="rounded-2xl border border-white/10 bg-black/20 p-3">
              <div class="flex flex-wrap items-center gap-2">
                <span class="font-mono text-sm text-white">{{ finding.code }}</span>
                <span class="rounded-full bg-amber-300/10 px-2 py-1 text-xs text-amber-100">{{ finding.severity || 'review' }}</span>
                <span class="text-xs text-slate-500">count={{ finding.count ?? 1 }}</span>
              </div>
              <p class="mt-2 text-sm text-slate-400">{{ finding.description || '—' }}</p>
            </div>
          </div>
        </div>
      </div>

      <div class="mt-6 rounded-3xl border border-white/10 bg-black/20 p-4">
        <button type="button" class="text-sm font-semibold text-cyan-100" @click="showRows = !showRows">
          {{ showRows ? $t('compliance.workspace.hideRows') : $t('compliance.workspace.showRows') }}
        </button>
        <pre v-if="showRows" class="mt-4 max-h-96 overflow-auto rounded-2xl bg-black/40 p-4 text-xs text-slate-300"><code>{{ rowsPreview }}</code></pre>
      </div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { parseComplianceJSON, type ComplianceReportSummary } from '../../utils/complianceReports'

const { t } = useI18n()
const summary = ref<ComplianceReportSummary | null>(null)
const error = ref('')
const fileName = ref('')
const showRows = ref(false)

const cards = computed(() => {
  if (!summary.value) return []
  return [
    { label: t('compliance.workspace.cards.status'), value: summary.value.status, className: statusClass(summary.value.status) },
    { label: t('compliance.workspace.cards.total'), value: String(summary.value.total), className: 'text-white' },
    { label: t('compliance.workspace.cards.passed'), value: String(summary.value.passed), className: 'text-emerald-200' },
    { label: t('compliance.workspace.cards.failed'), value: String(summary.value.failed), className: 'text-red-200' },
    { label: t('compliance.workspace.cards.notCollected'), value: String(summary.value.notCollected), className: 'text-amber-200' },
    { label: t('compliance.workspace.cards.findings'), value: String(summary.value.findings.length), className: 'text-cyan-100' }
  ]
})

const rowsPreview = computed(() => JSON.stringify(summary.value?.rows ?? [], null, 2))

function statusClass(status: string) {
  if (status === 'ok') return 'text-emerald-200'
  if (status === 'fail') return 'text-red-200'
  if (status === 'warn') return 'text-amber-200'
  return 'text-slate-200'
}

async function onFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  fileName.value = file.name
  error.value = ''
  showRows.value = false
  try {
    summary.value = parseComplianceJSON(await file.text())
  } catch {
    summary.value = null
    error.value = t('compliance.workspace.invalidJson')
  } finally {
    input.value = ''
  }
}
</script>
