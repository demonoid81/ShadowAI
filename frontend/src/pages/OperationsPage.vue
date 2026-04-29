<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 max-w-5xl">
        <div class="mb-5 flex flex-wrap gap-2">
          <span v-for="tag in tags" :key="tag" class="tag-chip">{{ $t(tag) }}</span>
        </div>
        <h2 class="text-4xl font-semibold tracking-tight text-white sm:text-5xl">
          {{ $t('operations.title') }}
        </h2>
        <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">
          {{ $t('operations.subtitle') }}
        </p>
      </div>
    </section>

    <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <article v-for="card in cards" :key="card.titleKey" class="posture-card">
        <div class="flex items-center justify-between">
          <span class="text-xs uppercase tracking-[0.22em] text-slate-500">{{ card.track }}</span>
          <span class="rounded-full bg-cyan-400/10 px-3 py-1 text-xs font-semibold text-cyan-100">
            {{ $t('operations.staticCapability') }}
          </span>
        </div>
        <h3 class="mt-4 text-lg font-semibold text-white">{{ $t(card.titleKey) }}</h3>
        <p class="mt-3 text-sm leading-6 text-slate-400">{{ $t(card.bodyKey) }}</p>
      </article>
    </section>

    <OperationLiveSignals />

    <section class="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
      <div class="console-card">
        <div class="section-kicker">{{ $t('operations.runbookKicker') }}</div>
        <h3 class="section-title">{{ $t('operations.runbookTitle') }}</h3>
        <div class="mt-6 space-y-3">
          <div v-for="step in runbook" :key="step.titleKey" class="rounded-2xl border border-white/10 bg-white/[0.035] p-4">
            <div class="text-sm font-semibold text-white">{{ $t(step.titleKey) }}</div>
            <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t(step.bodyKey) }}</p>
          </div>
        </div>
      </div>

      <div class="console-card">
        <div class="section-kicker">{{ $t('operations.commandsKicker') }}</div>
        <h3 class="section-title">{{ $t('operations.commandsTitle') }}</h3>
        <div class="mt-6 space-y-4">
          <div v-for="cmd in commands" :key="cmd.titleKey" class="rounded-2xl border border-white/10 bg-slate-950/70 p-4">
            <div class="mb-3 text-sm font-semibold text-slate-200">{{ $t(cmd.titleKey) }}</div>
            <pre class="overflow-x-auto rounded-xl bg-black/40 p-3 text-xs leading-5 text-cyan-100"><code>{{ cmd.command }}</code></pre>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import OperationLiveSignals from '../components/operations/OperationLiveSignals.vue'

const tags = ['operations.tags.prod', 'operations.tags.alerts', 'operations.tags.restore', 'operations.tags.byok']

const cards = [
  { track: 'PROD1', titleKey: 'operations.cards.validation.title', bodyKey: 'operations.cards.validation.body' },
  { track: 'SIEM', titleKey: 'operations.cards.siem.title', bodyKey: 'operations.cards.siem.body' },
  { track: 'W7', titleKey: 'operations.cards.restore.title', bodyKey: 'operations.cards.restore.body' },
  { track: 'BYOK', titleKey: 'operations.cards.byok.title', bodyKey: 'operations.cards.byok.body' }
]

const runbook = [
  { titleKey: 'operations.runbook.preflight.title', bodyKey: 'operations.runbook.preflight.body' },
  { titleKey: 'operations.runbook.deploy.title', bodyKey: 'operations.runbook.deploy.body' },
  { titleKey: 'operations.runbook.evidence.title', bodyKey: 'operations.runbook.evidence.body' },
  { titleKey: 'operations.runbook.archive.title', bodyKey: 'operations.runbook.archive.body' }
]

const commands = [
  { titleKey: 'operations.commands.validate', command: 'shadowai-prod-validate --chart ./deploy/helm/shadowai --values ./deploy/helm/shadowai/values-prod.yaml --live --base-url https://shadowai.example.com' },
  { titleKey: 'operations.commands.restore', command: 'audit-verify --restore-drill --table all --signing-keyring ./signing-keyring.json --chain-keyring ./chain-keyring.json' },
  { titleKey: 'operations.commands.byok', command: 'audit-byok-sweep --database-url "$DATABASE_URL" --dry-run --limit 1000' },
  { titleKey: 'operations.commands.smoke', command: 'go test -tags "enterprise smoke" ./smoke/... -count=1 -timeout 15m' }
]
</script>
