<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 grid gap-8 xl:grid-cols-[1.15fr_0.85fr] xl:items-end">
        <div>
          <div class="mb-5 flex flex-wrap gap-2">
            <span v-for="tag in tags" :key="tag" class="tag-chip">{{ $t(tag) }}</span>
          </div>
          <h2 class="text-4xl font-semibold tracking-tight text-white sm:text-5xl">
            {{ $t('settings.title') }}
          </h2>
          <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">
            {{ $t('settings.subtitle') }}
          </p>
        </div>
        <div class="rounded-3xl border border-white/10 bg-slate-950/70 p-5">
          <div class="section-kicker">{{ $t('settings.boundaryKicker') }}</div>
          <p class="mt-3 text-sm leading-6 text-slate-300">{{ $t('settings.boundaryText') }}</p>
        </div>
      </div>
    </section>

    <section class="console-card">
      <div class="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div class="section-kicker">{{ $t('settings.liveKicker') }}</div>
          <h3 class="section-title">{{ $t('settings.liveTitle') }}</h3>
        </div>
        <button
          @click="refreshSignals"
          :disabled="refreshing"
          class="rounded-2xl border border-cyan-200/20 px-4 py-2 text-sm font-semibold text-cyan-100 transition-colors hover:bg-cyan-300/10 disabled:opacity-50"
        >
          {{ refreshing ? $t('settings.refreshing') : $t('settings.refresh') }}
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
          <p class="mt-4 text-sm leading-6 text-slate-400">{{ signal.detail }}</p>
          <div class="mt-5 rounded-2xl border border-white/10 bg-slate-950/50 px-4 py-3 text-xs text-slate-500">
            {{ $t(signal.sourceKey) }}
          </div>
        </article>
      </div>
    </section>

    <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <article v-for="control in controlFamilies" :key="control.titleKey" class="posture-card">
        <div class="flex items-start justify-between gap-4">
          <div>
            <div class="text-xs uppercase tracking-[0.22em] text-slate-500">{{ control.track }}</div>
            <h3 class="mt-3 text-lg font-semibold text-white">{{ $t(control.titleKey) }}</h3>
          </div>
          <span class="rounded-full px-3 py-1 text-xs font-semibold" :class="statusClass(control.status)">
            {{ $t(statusLabel(control.status)) }}
          </span>
        </div>
        <p class="mt-4 text-sm leading-6 text-slate-400">{{ $t(control.bodyKey) }}</p>
        <div class="mt-5 rounded-2xl border border-white/10 bg-slate-950/50 px-4 py-3 text-xs text-slate-500">
          {{ $t(control.sourceKey) }}
        </div>
      </article>
    </section>

    <section class="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
      <div class="console-card">
        <div class="section-kicker">{{ $t('settings.noSecretsKicker') }}</div>
        <h3 class="section-title">{{ $t('settings.noSecretsTitle') }}</h3>
        <div class="mt-6 space-y-3">
          <div v-for="item in noSecretItems" :key="item" class="rounded-2xl border border-white/10 bg-white/[0.035] px-4 py-3 text-sm text-slate-300">
            {{ $t(item) }}
          </div>
        </div>
      </div>

      <div class="console-card">
        <div class="section-kicker">{{ $t('settings.nextKicker') }}</div>
        <h3 class="section-title">{{ $t('settings.nextTitle') }}</h3>
        <div class="mt-6 space-y-4">
          <div v-for="item in nextActions" :key="item.titleKey" class="rounded-2xl border border-white/10 bg-slate-950/70 p-4">
            <div class="text-sm font-semibold text-slate-200">{{ $t(item.titleKey) }}</div>
            <p class="mt-2 text-sm leading-6 text-slate-500">{{ $t(item.bodyKey) }}</p>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api, { proxyApi } from '../api/client'

type SignalStatus = 'loading' | 'ok' | 'warn' | 'error' | 'unknown' | 'checklist'

interface SignalState {
  status: SignalStatus
  detail: string
}

const { t } = useI18n()

const tags = ['settings.tags.readOnly', 'settings.tags.noSecrets', 'settings.tags.liveSignals', 'settings.tags.checklists']
const refreshing = ref(false)

const readiness = ref<SignalState>({ status: 'loading', detail: t('settings.live.readiness.loading') })
const firewall = ref<SignalState>({ status: 'loading', detail: t('settings.live.firewall.loading') })
const audit = ref<SignalState>({ status: 'loading', detail: t('settings.live.audit.loading') })
const providers = ref<SignalState>({ status: 'loading', detail: t('settings.live.providers.loading') })

const liveSignals = computed(() => [
  { key: 'readiness', kickerKey: 'settings.live.readiness.kicker', titleKey: 'settings.live.readiness.title', sourceKey: 'settings.live.readiness.source', ...readiness.value },
  { key: 'firewall', kickerKey: 'settings.live.firewall.kicker', titleKey: 'settings.live.firewall.title', sourceKey: 'settings.live.firewall.source', ...firewall.value },
  { key: 'audit', kickerKey: 'settings.live.audit.kicker', titleKey: 'settings.live.audit.title', sourceKey: 'settings.live.audit.source', ...audit.value },
  { key: 'providers', kickerKey: 'settings.live.providers.kicker', titleKey: 'settings.live.providers.title', sourceKey: 'settings.live.providers.source', ...providers.value }
])

const controlFamilies = [
  { track: 'Identity', status: 'checklist' as SignalStatus, titleKey: 'settings.controls.identity.title', bodyKey: 'settings.controls.identity.body', sourceKey: 'settings.controls.identity.source' },
  { track: 'SIEM', status: 'checklist' as SignalStatus, titleKey: 'settings.controls.siem.title', bodyKey: 'settings.controls.siem.body', sourceKey: 'settings.controls.siem.source' },
  { track: 'Evidence', status: 'checklist' as SignalStatus, titleKey: 'settings.controls.evidence.title', bodyKey: 'settings.controls.evidence.body', sourceKey: 'settings.controls.evidence.source' },
  { track: 'Streaming', status: 'checklist' as SignalStatus, titleKey: 'settings.controls.streaming.title', bodyKey: 'settings.controls.streaming.body', sourceKey: 'settings.controls.streaming.source' },
  { track: 'BYOK', status: 'checklist' as SignalStatus, titleKey: 'settings.controls.byok.title', bodyKey: 'settings.controls.byok.body', sourceKey: 'settings.controls.byok.source' },
  { track: 'PROD1', status: 'checklist' as SignalStatus, titleKey: 'settings.controls.production.title', bodyKey: 'settings.controls.production.body', sourceKey: 'settings.controls.production.source' }
]

const noSecretItems = [
  'settings.noSecrets.items.apiKeys',
  'settings.noSecrets.items.tokens',
  'settings.noSecrets.items.endpoints',
  'settings.noSecrets.items.runtime'
]

const nextActions = [
  { titleKey: 'settings.next.tenant.title', bodyKey: 'settings.next.tenant.body' },
  { titleKey: 'settings.next.auth.title', bodyKey: 'settings.next.auth.body' },
  { titleKey: 'settings.next.ops.title', bodyKey: 'settings.next.ops.body' }
]

function statusLabel(status: SignalStatus): string {
  return `settings.status.${status}`
}

function statusClass(status: SignalStatus): string {
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

async function fetchReadiness() {
  readiness.value = { status: 'loading', detail: t('settings.live.readiness.loading') }
  try {
    const { data } = await api.get('/ready', { validateStatus: () => true })
    const checks = data?.checks || {}
    const failed = Object.entries(checks).filter(([, value]) => !(value as any)?.ok).map(([key]) => key)
    if (data?.ready === true) {
      readiness.value = { status: 'ok', detail: t('settings.live.readiness.ok') }
      return
    }
    readiness.value = {
      status: 'error',
      detail: failed.length > 0 ? t('settings.live.readiness.failedWithChecks', { checks: failed.join(', ') }) : t('settings.live.readiness.failed')
    }
  } catch {
    readiness.value = { status: 'unknown', detail: t('settings.live.readiness.unknown') }
  }
}

async function fetchFirewall() {
  firewall.value = { status: 'loading', detail: t('settings.live.firewall.loading') }
  try {
    const { data } = await proxyApi.get('/firewall/status')
    const inspectors = Array.isArray(data?.inspectors) ? data.inspectors : []
    const enabled = inspectors.filter((item: any) => item?.enabled).length
    if (!data?.enabled) {
      firewall.value = { status: 'warn', detail: t('settings.live.firewall.disabled') }
      return
    }
    firewall.value = { status: 'ok', detail: t('settings.live.firewall.ok', { enabled, total: inspectors.length }) }
  } catch {
    firewall.value = { status: 'unknown', detail: t('settings.live.firewall.unknown') }
  }
}

async function fetchAudit() {
  audit.value = { status: 'loading', detail: t('settings.live.audit.loading') }
  try {
    const { data } = await api.get('/audit/status')
    audit.value = {
      status: 'ok',
      detail: t('settings.live.audit.ok', {
        mode: data?.payload_mode || 'unknown',
        days: data?.retention_days ?? 'unknown',
        purged: data?.rows_purged_total ?? 0
      })
    }
  } catch {
    audit.value = { status: 'unknown', detail: t('settings.live.audit.unknown') }
  }
}

async function fetchProviders() {
  providers.value = { status: 'loading', detail: t('settings.live.providers.loading') }
  try {
    const { data } = await proxyApi.get('/providers/connectivity')
    const summary = data?.summary || {}
    const total = Number(summary.total || 0)
    const reachable = Number(summary.reachable || 0)
    const problems = Number(summary.egress_blocked || 0) + Number(summary.not_checked || 0) + Number(summary.stale || 0)
    if (total === 0) {
      providers.value = { status: 'unknown', detail: t('settings.live.providers.none') }
      return
    }
    providers.value = {
      status: problems > 0 || reachable < total ? 'warn' : 'ok',
      detail: t('settings.live.providers.ok', { reachable, total, problems })
    }
  } catch {
    providers.value = { status: 'unknown', detail: t('settings.live.providers.unknown') }
  }
}

async function refreshSignals() {
  refreshing.value = true
  await Promise.allSettled([fetchReadiness(), fetchFirewall(), fetchAudit(), fetchProviders()])
  refreshing.value = false
}

onMounted(refreshSignals)
</script>
