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
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
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

const refreshing = ref(false)
const health = ref<OperationSignalSummary>(loadingSignal('operations.live.health.loading'))
const readiness = ref<OperationSignalSummary>(loadingSignal('operations.live.readiness.loading'))
const firewall = ref<OperationSignalSummary>(loadingSignal('operations.live.firewall.loading'))
const audit = ref<OperationSignalSummary>(loadingSignal('operations.live.audit.loading'))

const liveSignals = computed(() => [
  { key: 'health', kickerKey: 'operations.live.health.kicker', titleKey: 'operations.live.health.title', sourceKey: 'operations.live.health.source', ...health.value },
  { key: 'readiness', kickerKey: 'operations.live.readiness.kicker', titleKey: 'operations.live.readiness.title', sourceKey: 'operations.live.readiness.source', ...readiness.value },
  { key: 'firewall', kickerKey: 'operations.live.firewall.kicker', titleKey: 'operations.live.firewall.title', sourceKey: 'operations.live.firewall.source', ...firewall.value },
  { key: 'audit', kickerKey: 'operations.live.audit.kicker', titleKey: 'operations.live.audit.title', sourceKey: 'operations.live.audit.source', ...audit.value }
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

async function refreshSignals() {
  refreshing.value = true
  await Promise.allSettled([fetchHealth(), fetchReadiness(), fetchFirewall(), fetchAudit()])
  refreshing.value = false
}

onMounted(refreshSignals)
</script>
