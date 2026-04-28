<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 grid gap-8 xl:grid-cols-[1.2fr_0.8fr] xl:items-end">
        <div>
          <div class="mb-5 flex flex-wrap gap-2">
            <span v-for="tag in heroTags" :key="tag" class="tag-chip">{{ $t(tag) }}</span>
          </div>
          <h2 class="max-w-4xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
            {{ $t('dashboard.consoleTitle') }}
          </h2>
          <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">
            {{ $t('dashboard.consoleSubtitle') }}
          </p>
        </div>

        <div class="rounded-3xl border border-white/10 bg-slate-950/60 p-5 shadow-2xl shadow-cyan-950/20">
          <div class="flex items-center justify-between">
            <span class="text-xs uppercase tracking-[0.26em] text-slate-500">{{ $t('dashboard.readiness') }}</span>
            <span class="rounded-full bg-emerald-400/15 px-3 py-1 text-xs font-semibold text-emerald-200">
              {{ $t('dashboard.operatorValidated') }}
            </span>
          </div>
          <div class="mt-5 space-y-4">
            <div v-for="item in readinessItems" :key="item.labelKey">
              <div class="mb-1 flex items-center justify-between text-sm">
                <span class="text-slate-300">{{ $t(item.labelKey) }}</span>
                <span class="font-semibold" :class="item.textColor">{{ item.value }}</span>
              </div>
              <div class="h-2 rounded-full bg-white/10">
                <div class="h-2 rounded-full" :class="item.barColor" :style="{ width: item.width }" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <article v-for="card in postureCards" :key="card.titleKey" class="posture-card">
        <div class="flex items-start justify-between gap-4">
          <div>
            <div class="text-xs uppercase tracking-[0.22em] text-slate-500">{{ $t(card.kickerKey) }}</div>
            <h3 class="mt-3 text-lg font-semibold text-white">{{ $t(card.titleKey) }}</h3>
          </div>
          <div class="rounded-2xl border px-3 py-1 text-xs font-semibold" :class="card.badgeClass">
            {{ $t(card.badgeKey) }}
          </div>
        </div>
        <p class="mt-4 min-h-16 text-sm leading-6 text-slate-400">{{ $t(card.bodyKey) }}</p>
        <div class="mt-5 flex items-center gap-2 text-xs text-slate-500">
          <span class="status-dot" :class="card.dotClass" />
          <span>{{ $t(card.signalKey) }}</span>
        </div>
      </article>
    </section>

    <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4" v-if="store.stats">
      <StatsCard :label="t('dashboard.totalRequests')" :value="store.stats.total_requests" format="number" />
      <StatsCard :label="t('dashboard.blockedRequests')" :value="store.stats.blocked_requests" format="number" color="text-red-300" />
      <StatsCard :label="t('dashboard.totalCost')" :value="store.stats.total_cost" format="currency" color="text-emerald-300" />
      <StatsCard :label="t('dashboard.activeUsers')" :value="store.stats.active_users" format="number" color="text-cyan-300" />
    </section>

    <section class="grid gap-6 xl:grid-cols-[1.35fr_0.65fr]">
      <div class="console-card">
        <div class="mb-5 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div class="section-kicker">{{ $t('dashboard.trafficKicker') }}</div>
            <h3 class="section-title">{{ $t('dashboard.trafficTitle') }}</h3>
          </div>
          <div class="text-sm text-slate-500">{{ $t('dashboard.trafficSubtitle') }}</div>
        </div>
        <UsageChart :data="store.usage" />
      </div>

      <div class="console-card">
        <div class="section-kicker">{{ $t('dashboard.securityKicker') }}</div>
        <h3 class="section-title">{{ $t('dashboard.securityTitle') }}</h3>
        <div class="mt-6 space-y-4">
          <div v-for="signal in securitySignals" :key="signal.labelKey" class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
            <div class="flex items-center justify-between">
              <span class="text-sm font-medium text-slate-200">{{ $t(signal.labelKey) }}</span>
              <span class="text-sm font-semibold" :class="signal.color">{{ signal.value }}</span>
            </div>
            <p class="mt-2 text-xs leading-5 text-slate-500">{{ $t(signal.detailKey) }}</p>
          </div>
        </div>
      </div>
    </section>

    <section class="console-card">
      <div class="mb-5 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div class="section-kicker">{{ $t('dashboard.identityKicker') }}</div>
          <h3 class="section-title">{{ $t('dashboard.topUsers') }}</h3>
        </div>
        <div class="text-sm text-slate-500">{{ $t('dashboard.maskedIdentityNote') }}</div>
      </div>
      <div class="overflow-hidden rounded-2xl border border-white/10">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-white/10 bg-white/[0.03] text-left text-xs uppercase tracking-[0.18em] text-slate-500">
              <th class="px-4 py-3">{{ $t('dashboard.userIdShort') }}</th>
              <th class="px-4 py-3">{{ $t('dashboard.emailMasked') }}</th>
              <th class="px-4 py-3">{{ $t('dashboard.requests') }}</th>
              <th class="px-4 py-3">{{ $t('dashboard.cost') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in store.topUsers" :key="u.user_id" class="border-b border-white/5 last:border-0">
              <td class="px-4 py-3 font-mono text-xs text-slate-500">{{ u.user_id?.slice(0, 8) }}...</td>
              <td class="px-4 py-3 text-slate-200">{{ u.email_masked }}</td>
              <td class="px-4 py-3 text-slate-400">{{ u.requests }}</td>
              <td class="px-4 py-3 text-emerald-300">${{ u.cost?.toFixed(4) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useDashboardStore } from '../stores/dashboard'
import StatsCard from '../components/StatsCard.vue'
import UsageChart from '../components/UsageChart.vue'

const { t } = useI18n()
const store = useDashboardStore()

const heroTags = [
  'dashboard.tags.firewall',
  'dashboard.tags.evidence',
  'dashboard.tags.tenant',
  'dashboard.tags.byok'
]

const postureCards = [
  {
    kickerKey: 'dashboard.cards.protect.kicker',
    titleKey: 'dashboard.cards.protect.title',
    bodyKey: 'dashboard.cards.protect.body',
    badgeKey: 'dashboard.cards.protect.badge',
    signalKey: 'dashboard.cards.protect.signal',
    badgeClass: 'border-red-300/20 bg-red-400/10 text-red-100',
    dotClass: 'bg-red-300'
  },
  {
    kickerKey: 'dashboard.cards.govern.kicker',
    titleKey: 'dashboard.cards.govern.title',
    bodyKey: 'dashboard.cards.govern.body',
    badgeKey: 'dashboard.cards.govern.badge',
    signalKey: 'dashboard.cards.govern.signal',
    badgeClass: 'border-cyan-300/20 bg-cyan-400/10 text-cyan-100',
    dotClass: 'bg-cyan-300'
  },
  {
    kickerKey: 'dashboard.cards.evidence.kicker',
    titleKey: 'dashboard.cards.evidence.title',
    bodyKey: 'dashboard.cards.evidence.body',
    badgeKey: 'dashboard.cards.evidence.badge',
    signalKey: 'dashboard.cards.evidence.signal',
    badgeClass: 'border-emerald-300/20 bg-emerald-400/10 text-emerald-100',
    dotClass: 'bg-emerald-300'
  },
  {
    kickerKey: 'dashboard.cards.operate.kicker',
    titleKey: 'dashboard.cards.operate.title',
    bodyKey: 'dashboard.cards.operate.body',
    badgeKey: 'dashboard.cards.operate.badge',
    signalKey: 'dashboard.cards.operate.signal',
    badgeClass: 'border-amber-300/20 bg-amber-400/10 text-amber-100',
    dotClass: 'bg-amber-300'
  }
]

const readinessItems = [
  { labelKey: 'dashboard.readinessItems.policy', value: 'G4', width: '100%', barColor: 'bg-cyan-300', textColor: 'text-cyan-200' },
  { labelKey: 'dashboard.readinessItems.evidence', value: 'W8', width: '100%', barColor: 'bg-emerald-300', textColor: 'text-emerald-200' },
  { labelKey: 'dashboard.readinessItems.identity', value: 'E3', width: '92%', barColor: 'bg-sky-300', textColor: 'text-sky-200' },
  { labelKey: 'dashboard.readinessItems.prod', value: 'PROD1', width: '88%', barColor: 'bg-amber-300', textColor: 'text-amber-200' }
]

const blockRate = computed(() => {
  const stats = store.stats
  if (!stats?.total_requests) return '0.0%'
  return `${((Number(stats.blocked_requests || 0) / Number(stats.total_requests)) * 100).toFixed(1)}%`
})

const securitySignals = computed(() => [
  {
    labelKey: 'dashboard.signals.blockRate',
    detailKey: 'dashboard.signals.blockRateDetail',
    value: blockRate.value,
    color: 'text-red-200'
  },
  {
    labelKey: 'dashboard.signals.siem',
    detailKey: 'dashboard.signals.siemDetail',
    value: 'S1.1',
    color: 'text-emerald-200'
  },
  {
    labelKey: 'dashboard.signals.streaming',
    detailKey: 'dashboard.signals.streamingDetail',
    value: 'F7.6',
    color: 'text-cyan-200'
  }
])

onMounted(() => {
  store.fetchStats()
  store.fetchUsage()
  store.fetchTopUsers()
})
</script>
