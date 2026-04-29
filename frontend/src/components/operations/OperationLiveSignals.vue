<template>
  <section class="console-card">
    <div class="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <div class="section-kicker">{{ $t('operations.liveKicker') }}</div>
        <h3 class="section-title">{{ $t('operations.liveTitle') }}</h3>
        <p class="mt-2 max-w-3xl text-sm leading-6 text-slate-400">{{ $t('operations.liveBoundary') }}</p>
      </div>
      <button
        type="button"
        :disabled="refreshing"
        class="rounded-2xl border border-cyan-200/20 px-4 py-2 text-sm font-semibold text-cyan-100 transition-colors hover:bg-cyan-300/10 disabled:opacity-50"
        @click="refreshSignals"
      >
        {{ refreshing ? $t('operations.refreshing') : $t('operations.refresh') }}
      </button>
    </div>

    <div class="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <article v-for="signal in liveSignals" :key="signal.key" class="rounded-3xl border border-white/10 bg-white/[0.035] p-5">
        <div class="flex items-start justify-between gap-4">
          <div>
            <div class="text-xs uppercase tracking-[0.22em] text-slate-500">{{ $t(signal.kickerKey) }}</div>
            <h4 class="mt-3 text-base font-semibold text-white">{{ $t(signal.titleKey) }}</h4>
          </div>
          <span class="rounded-full px-3 py-1 text-xs font-semibold" :class="statusClass(signal.status)">
            {{ $t(statusLabel(signal.status)) }}
          </span>
        </div>
        <p class="mt-4 text-sm leading-6 text-slate-400">{{ $t(signal.detailKey, signal.params || {}) }}</p>
        <div class="mt-5 rounded-2xl border border-white/10 bg-slate-950/50 px-4 py-3 text-xs text-slate-500">
          {{ $t(signal.sourceKey) }}
        </div>
      </article>
    </div>

    <div class="mt-8 rounded-3xl border border-white/10 bg-slate-950/45 p-5">
      <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div class="text-xs uppercase tracking-[0.22em] text-slate-500">{{ $t('operations.productionKicker') }}</div>
          <h4 class="mt-3 text-lg font-semibold text-white">{{ $t('operations.productionTitle') }}</h4>
          <p class="mt-2 max-w-3xl text-sm leading-6 text-slate-400">{{ $t('operations.productionBoundary') }}</p>
        </div>
        <div v-if="productionGeneratedAt" class="rounded-2xl border border-white/10 bg-black/20 px-4 py-3 text-xs text-slate-500">
          {{ $t('operations.generatedAt') }}: <span class="font-mono text-slate-300">{{ productionGeneratedAt }}</span>
        </div>
      </div>

      <div v-if="productionLoading" class="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
        {{ $t('operations.productionLoading') }}
      </div>
      <div v-else-if="productionError" class="mt-5 rounded-2xl border border-slate-300/20 bg-slate-400/10 p-4 text-sm text-slate-300">
        {{ $t('operations.productionUnknown') }}
      </div>
      <template v-else>
        <div class="mt-5 grid gap-3 md:grid-cols-5">
          <div v-for="item in summaryCards" :key="item.labelKey" class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
            <div class="text-xs uppercase tracking-[0.18em] text-slate-500">{{ $t(item.labelKey) }}</div>
            <div class="mt-2 text-2xl font-semibold" :class="item.className">{{ item.value }}</div>
          </div>
        </div>

        <div class="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <article v-for="signal in productionSignals" :key="signal.key" class="rounded-2xl border border-white/10 bg-black/20 p-4">
            <div class="flex items-start justify-between gap-3">
              <div>
                <div class="text-xs uppercase tracking-[0.18em] text-slate-500">{{ signal.source }}</div>
                <h5 class="mt-2 text-sm font-semibold text-white">{{ productionSignalTitle(signal.key) }}</h5>
              </div>
              <span class="rounded-full px-2 py-1 text-xs font-semibold" :class="statusClass(signal.status)">
                {{ $t(statusLabel(signal.status)) }}
              </span>
            </div>
            <p class="mt-3 text-sm leading-6 text-slate-400">{{ signal.message }}</p>
            <p v-if="formatDetails(signal.details)" class="mt-3 break-words font-mono text-xs leading-5 text-slate-500">
              {{ formatDetails(signal.details) }}
            </p>
          </article>
        </div>
      </template>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api, { proxyApi } from '../../api/client'
import {
  loadingSignal,
  summarizeAuditStatus,
  summarizeFirewall,
  summarizeLiveness,
  summarizeReadiness,
  unknownSignal,
  type OperationSignalStatus,
  type OperationSignalSummary
} from '../../utils/operationsHealth'

interface ProductionSignal {
  key: string
  status: OperationSignalStatus
  source: string
  message: string
  details?: Record<string, unknown>
}

interface ProductionSummary {
  total: number
  ok: number
  warn: number
  error: number
  unknown: number
}

const refreshing = ref(false)
const { t } = useI18n()
const health = ref<OperationSignalSummary>(loadingSignal('operations.live.health.loading'))
const readiness = ref<OperationSignalSummary>(loadingSignal('operations.live.readiness.loading'))
const firewall = ref<OperationSignalSummary>(loadingSignal('operations.live.firewall.loading'))
const audit = ref<OperationSignalSummary>(loadingSignal('operations.live.audit.loading'))
const productionLoading = ref(false)
const productionError = ref('')
const productionGeneratedAt = ref('')
const productionSummary = ref<ProductionSummary>({ total: 0, ok: 0, warn: 0, error: 0, unknown: 0 })
const productionSignals = ref<ProductionSignal[]>([])

const liveSignals = computed(() => [
  { key: 'health', kickerKey: 'operations.live.health.kicker', titleKey: 'operations.live.health.title', sourceKey: 'operations.live.health.source', ...health.value },
  { key: 'readiness', kickerKey: 'operations.live.readiness.kicker', titleKey: 'operations.live.readiness.title', sourceKey: 'operations.live.readiness.source', ...readiness.value },
  { key: 'firewall', kickerKey: 'operations.live.firewall.kicker', titleKey: 'operations.live.firewall.title', sourceKey: 'operations.live.firewall.source', ...firewall.value },
  { key: 'audit', kickerKey: 'operations.live.audit.kicker', titleKey: 'operations.live.audit.title', sourceKey: 'operations.live.audit.source', ...audit.value }
])

const summaryCards = computed(() => [
  { labelKey: 'operations.summary.total', value: String(productionSummary.value.total), className: 'text-white' },
  { labelKey: 'operations.summary.ok', value: String(productionSummary.value.ok), className: 'text-emerald-200' },
  { labelKey: 'operations.summary.warn', value: String(productionSummary.value.warn), className: 'text-amber-200' },
  { labelKey: 'operations.summary.error', value: String(productionSummary.value.error), className: 'text-red-200' },
  { labelKey: 'operations.summary.unknown', value: String(productionSummary.value.unknown), className: 'text-slate-300' }
])

function statusLabel(status: OperationSignalStatus): string {
  return `operations.status.${status}`
}

function statusClass(status: OperationSignalStatus): string {
  switch (status) {
    case 'ok':
      return 'bg-emerald-400/10 text-emerald-100'
    case 'warn':
      return 'bg-amber-400/10 text-amber-100'
    case 'error':
      return 'bg-red-400/10 text-red-100'
    case 'loading':
      return 'bg-sky-400/10 text-sky-100'
    case 'checklist':
      return 'bg-cyan-400/10 text-cyan-100'
    case 'unknown':
    default:
      return 'bg-slate-400/10 text-slate-300'
  }
}

async function fetchHealth() {
  health.value = loadingSignal('operations.live.health.loading')
  try {
    const { data } = await api.get('/health')
    health.value = summarizeLiveness(data)
  } catch {
    health.value = unknownSignal('operations.live.health.unknown')
  }
}

async function fetchReadiness() {
  readiness.value = loadingSignal('operations.live.readiness.loading')
  try {
    const { data } = await api.get('/ready', { validateStatus: () => true })
    readiness.value = summarizeReadiness(data)
  } catch {
    readiness.value = unknownSignal('operations.live.readiness.unknown')
  }
}

async function fetchFirewall() {
  firewall.value = loadingSignal('operations.live.firewall.loading')
  try {
    const { data } = await proxyApi.get('/firewall/status')
    firewall.value = summarizeFirewall(data)
  } catch {
    firewall.value = unknownSignal('operations.live.firewall.unknown')
  }
}

async function fetchAudit() {
  audit.value = loadingSignal('operations.live.audit.loading')
  try {
    const { data } = await api.get('/audit/status')
    audit.value = summarizeAuditStatus(data)
  } catch {
    audit.value = unknownSignal('operations.live.audit.unknown')
  }
}

async function fetchProductionStatus() {
  productionLoading.value = true
  productionError.value = ''
  try {
    const { data } = await api.get('/operations/status')
    productionGeneratedAt.value = typeof data?.generated_at === 'string' ? data.generated_at : ''
    productionSummary.value = normalizeSummary(data?.summary)
    productionSignals.value = Array.isArray(data?.signals) ? data.signals.map(normalizeSignal) : []
  } catch {
    productionGeneratedAt.value = ''
    productionSummary.value = { total: 1, ok: 0, warn: 0, error: 0, unknown: 1 }
    productionSignals.value = []
    productionError.value = 'unknown'
  } finally {
    productionLoading.value = false
  }
}

async function refreshSignals() {
  refreshing.value = true
  await Promise.allSettled([fetchHealth(), fetchReadiness(), fetchFirewall(), fetchAudit(), fetchProductionStatus()])
  refreshing.value = false
}

function normalizeSummary(raw: any): ProductionSummary {
  return {
    total: Number(raw?.total || 0),
    ok: Number(raw?.ok || 0),
    warn: Number(raw?.warn || 0),
    error: Number(raw?.error || 0),
    unknown: Number(raw?.unknown || 0)
  }
}

function normalizeSignal(raw: any): ProductionSignal {
  return {
    key: String(raw?.key || 'unknown'),
    status: normalizeStatus(raw?.status),
    source: String(raw?.source || 'unknown'),
    message: String(raw?.message || ''),
    details: raw?.details && typeof raw.details === 'object' ? raw.details : undefined
  }
}

function normalizeStatus(value: unknown): OperationSignalStatus {
  if (value === 'ok' || value === 'warn' || value === 'error' || value === 'unknown') return value
  return 'unknown'
}

function productionSignalTitle(key: string): string {
  const translated = `operations.backendSignals.${key}`
  const value = t(translated)
  return value === translated ? key : value
}

function formatDetails(details?: Record<string, unknown>): string {
  if (!details) return ''
  return Object.entries(details)
    .map(([key, value]) => `${key}=${formatDetailValue(value)}`)
    .join(' · ')
}

function formatDetailValue(value: unknown): string {
  if (Array.isArray(value)) return value.join(',')
  if (value && typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

onMounted(refreshSignals)
</script>
