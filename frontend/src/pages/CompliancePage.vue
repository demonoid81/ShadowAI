<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 grid gap-8 xl:grid-cols-[1.1fr_0.9fr] xl:items-end">
        <div>
          <div class="mb-5 flex flex-wrap gap-2">
            <span v-for="tag in tags" :key="tag" class="tag-chip">{{ $t(tag) }}</span>
          </div>
          <h2 class="text-4xl font-semibold tracking-tight text-white sm:text-5xl">
            {{ $t('compliance.title') }}
          </h2>
          <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">
            {{ $t('compliance.subtitle') }}
          </p>
        </div>
        <div class="rounded-3xl border border-white/10 bg-slate-950/70 p-5">
          <div class="section-kicker">{{ $t('compliance.disclaimerKicker') }}</div>
          <p class="mt-3 text-sm leading-6 text-slate-300">{{ $t('compliance.disclaimer') }}</p>
        </div>
      </div>
    </section>

    <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <article v-for="control in controls" :key="control.titleKey" class="posture-card">
        <div class="text-xs uppercase tracking-[0.22em] text-slate-500">{{ control.track }}</div>
        <h3 class="mt-3 text-lg font-semibold text-white">{{ $t(control.titleKey) }}</h3>
        <p class="mt-4 text-sm leading-6 text-slate-400">{{ $t(control.bodyKey) }}</p>
        <div class="mt-5 rounded-2xl border border-white/10 bg-slate-950/50 px-4 py-3 text-xs text-slate-500">
          {{ $t(control.artifactKey) }}
        </div>
      </article>
    </section>

    <section class="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
      <div class="console-card">
        <div class="section-kicker">{{ $t('compliance.packageKicker') }}</div>
        <h3 class="section-title">{{ $t('compliance.packageTitle') }}</h3>
        <div class="mt-6 space-y-3">
          <div v-for="item in packageItems" :key="item.labelKey" class="flex items-center justify-between rounded-2xl border border-white/10 bg-white/[0.035] px-4 py-3">
            <span class="text-sm text-slate-300">{{ $t(item.labelKey) }}</span>
            <span class="rounded-full px-3 py-1 text-xs font-semibold" :class="item.badgeClass">{{ item.badge }}</span>
          </div>
        </div>
      </div>

      <div class="console-card">
        <div class="section-kicker">{{ $t('compliance.commandsKicker') }}</div>
        <h3 class="section-title">{{ $t('compliance.commandsTitle') }}</h3>
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
const tags = ['compliance.tags.soc2', 'compliance.tags.iso', 'compliance.tags.access', 'compliance.tags.evidence']

const controls = [
  { track: 'SOC1', titleKey: 'compliance.controls.mapping.title', bodyKey: 'compliance.controls.mapping.body', artifactKey: 'compliance.controls.mapping.artifact' },
  { track: 'SOC2.1', titleKey: 'compliance.controls.collect.title', bodyKey: 'compliance.controls.collect.body', artifactKey: 'compliance.controls.collect.artifact' },
  { track: 'SOC2.3', titleKey: 'compliance.controls.access.title', bodyKey: 'compliance.controls.access.body', artifactKey: 'compliance.controls.access.artifact' },
  { track: 'SEC1', titleKey: 'compliance.controls.validation.title', bodyKey: 'compliance.controls.validation.body', artifactKey: 'compliance.controls.validation.artifact' },
  { track: 'VRM1', titleKey: 'compliance.controls.vendor.title', bodyKey: 'compliance.controls.vendor.body', artifactKey: 'compliance.controls.vendor.artifact' },
  { track: 'Gaps', titleKey: 'compliance.controls.gaps.title', bodyKey: 'compliance.controls.gaps.body', artifactKey: 'compliance.controls.gaps.artifact' }
]

const packageItems = [
  { labelKey: 'compliance.package.mapping', badge: 'DOC', badgeClass: 'bg-cyan-400/10 text-cyan-100' },
  { labelKey: 'compliance.package.retention', badge: 'S3', badgeClass: 'bg-emerald-400/10 text-emerald-100' },
  { labelKey: 'compliance.package.chain', badge: 'WORM', badgeClass: 'bg-amber-400/10 text-amber-100' },
  { labelKey: 'compliance.package.access', badge: 'IAM', badgeClass: 'bg-sky-400/10 text-sky-100' },
  { labelKey: 'compliance.package.notCollected', badge: 'GAPS', badgeClass: 'bg-red-400/10 text-red-100' }
]

const commands = [
  { titleKey: 'compliance.commands.collect', command: 'audit-collect-evidence --from 2026-01-01 --to 2026-03-31 --output evidence-Q1.zip --format zip --allow-incomplete' },
  { titleKey: 'compliance.commands.access', command: 'audit-access-review --from 2026-01-01 --to 2026-03-31 --global --format json' },
  { titleKey: 'compliance.commands.retention', command: 'audit-evidence-report --bucket <bucket> --require-lock --min-retention-days 90 --format json' }
]
</script>
