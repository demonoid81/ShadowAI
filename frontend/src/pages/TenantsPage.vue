<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 max-w-5xl">
        <div class="mb-5 flex flex-wrap gap-2">
          <span v-for="tag in tags" :key="tag" class="tag-chip">{{ $t(tag) }}</span>
        </div>
        <h2 class="text-4xl font-semibold tracking-tight text-white sm:text-5xl">
          {{ $t('tenants.title') }}
        </h2>
        <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">
          {{ $t('tenants.subtitle') }}
        </p>
      </div>
    </section>

    <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <article v-for="control in controls" :key="control.titleKey" class="posture-card">
        <div class="flex items-start justify-between gap-4">
          <div>
            <div class="text-xs uppercase tracking-[0.22em] text-slate-500">{{ control.track }}</div>
            <h3 class="mt-3 text-lg font-semibold text-white">{{ $t(control.titleKey) }}</h3>
          </div>
          <span class="status-dot" :class="control.dotClass" />
        </div>
        <p class="mt-4 text-sm leading-6 text-slate-400">{{ $t(control.bodyKey) }}</p>
        <div class="mt-5 rounded-2xl border border-white/10 bg-slate-950/50 px-4 py-3 text-xs text-slate-500">
          {{ $t(control.artifactKey) }}
        </div>
      </article>
    </section>

    <section class="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
      <div class="console-card">
        <div class="section-kicker">{{ $t('tenants.flowKicker') }}</div>
        <h3 class="section-title">{{ $t('tenants.flowTitle') }}</h3>
        <div class="mt-6 space-y-3">
          <div v-for="(step, index) in lifecycle" :key="step.titleKey" class="rounded-2xl border border-white/10 bg-white/[0.035] p-4">
            <div class="flex gap-4">
              <span class="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-cyan-200/20 bg-cyan-200/10 text-xs font-bold text-cyan-100">
                {{ index + 1 }}
              </span>
              <div>
                <h4 class="text-sm font-semibold text-white">{{ $t(step.titleKey) }}</h4>
                <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t(step.bodyKey) }}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="console-card">
        <div class="section-kicker">{{ $t('tenants.commandsKicker') }}</div>
        <h3 class="section-title">{{ $t('tenants.commandsTitle') }}</h3>
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
const tags = ['tenants.tags.org', 'tenants.tags.scim', 'tenants.tags.globalAdmin', 'tenants.tags.budget']

const controls = [
  { track: 'T2', titleKey: 'tenants.controls.boundary.title', bodyKey: 'tenants.controls.boundary.body', artifactKey: 'tenants.controls.boundary.artifact', dotClass: 'bg-cyan-300' },
  { track: 'SCIM', titleKey: 'tenants.controls.scim.title', bodyKey: 'tenants.controls.scim.body', artifactKey: 'tenants.controls.scim.artifact', dotClass: 'bg-emerald-300' },
  { track: 'G4', titleKey: 'tenants.controls.budget.title', bodyKey: 'tenants.controls.budget.body', artifactKey: 'tenants.controls.budget.artifact', dotClass: 'bg-amber-300' },
  { track: 'W6', titleKey: 'tenants.controls.evidence.title', bodyKey: 'tenants.controls.evidence.body', artifactKey: 'tenants.controls.evidence.artifact', dotClass: 'bg-sky-300' },
  { track: 'Admin', titleKey: 'tenants.controls.global.title', bodyKey: 'tenants.controls.global.body', artifactKey: 'tenants.controls.global.artifact', dotClass: 'bg-purple-300' },
  { track: 'Purge', titleKey: 'tenants.controls.purge.title', bodyKey: 'tenants.controls.purge.body', artifactKey: 'tenants.controls.purge.artifact', dotClass: 'bg-red-300' }
]

const lifecycle = [
  { titleKey: 'tenants.lifecycle.create.title', bodyKey: 'tenants.lifecycle.create.body' },
  { titleKey: 'tenants.lifecycle.provision.title', bodyKey: 'tenants.lifecycle.provision.body' },
  { titleKey: 'tenants.lifecycle.govern.title', bodyKey: 'tenants.lifecycle.govern.body' },
  { titleKey: 'tenants.lifecycle.export.title', bodyKey: 'tenants.lifecycle.export.body' }
]

const commands = [
  { titleKey: 'tenants.commands.exportTenant', command: 'audit-export-evidence --org-id <uuid> --output ./tenant_bundle --zip' },
  { titleKey: 'tenants.commands.purgeTenant', command: 'audit-purge --target audit_logs --org-id <uuid> --cutoff 2026-01-01' },
  { titleKey: 'tenants.commands.verifyTenant', command: 'audit-verify --bundle ./tenant_bundle.zip --verbose' }
]
</script>
