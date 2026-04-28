<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 grid gap-8 xl:grid-cols-[1.05fr_0.95fr] xl:items-end">
        <div>
          <div class="mb-5 flex flex-wrap gap-2">
            <span v-for="tag in tags" :key="tag" class="tag-chip">{{ $t(tag) }}</span>
          </div>
          <h2 class="max-w-4xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
            {{ $t('evidence.title') }}
          </h2>
          <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">
            {{ $t('evidence.subtitle') }}
          </p>
        </div>

        <div class="rounded-3xl border border-white/10 bg-slate-950/70 p-5">
          <div class="section-kicker">{{ $t('evidence.contractKicker') }}</div>
          <div class="mt-5 grid gap-3">
            <div v-for="item in contracts" :key="item.labelKey" class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
              <div class="flex items-center justify-between gap-4">
                <span class="text-sm font-medium text-slate-200">{{ $t(item.labelKey) }}</span>
                <span class="rounded-full px-3 py-1 text-xs font-semibold" :class="item.badgeClass">
                  {{ item.code }}
                </span>
              </div>
              <p class="mt-2 text-xs leading-5 text-slate-500">{{ $t(item.detailKey) }}</p>
            </div>
          </div>
        </div>
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

    <section class="console-card">
      <div class="mb-6 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div class="section-kicker">{{ $t('evidence.pipelineKicker') }}</div>
          <h3 class="section-title">{{ $t('evidence.pipelineTitle') }}</h3>
        </div>
        <p class="max-w-xl text-sm leading-6 text-slate-500">{{ $t('evidence.pipelineNote') }}</p>
      </div>

      <div class="grid gap-3 xl:grid-cols-6">
        <div v-for="(step, index) in pipeline" :key="step.titleKey" class="relative rounded-3xl border border-white/10 bg-white/[0.035] p-4">
          <div class="mb-4 flex items-center justify-between">
            <span class="grid h-8 w-8 place-items-center rounded-xl border border-cyan-200/20 bg-cyan-200/10 text-xs font-bold text-cyan-100">
              {{ index + 1 }}
            </span>
            <span class="text-[0.65rem] uppercase tracking-[0.2em] text-slate-600">{{ step.code }}</span>
          </div>
          <h4 class="text-sm font-semibold text-white">{{ $t(step.titleKey) }}</h4>
          <p class="mt-2 text-xs leading-5 text-slate-500">{{ $t(step.bodyKey) }}</p>
        </div>
      </div>
    </section>

    <section class="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
      <div class="console-card">
        <div class="section-kicker">{{ $t('evidence.commandsKicker') }}</div>
        <h3 class="section-title">{{ $t('evidence.commandsTitle') }}</h3>
        <div class="mt-6 space-y-4">
          <div v-for="cmd in commands" :key="cmd.titleKey" class="rounded-2xl border border-white/10 bg-slate-950/70 p-4">
            <div class="mb-3 flex items-center justify-between">
              <span class="text-sm font-semibold text-slate-200">{{ $t(cmd.titleKey) }}</span>
              <span class="rounded-full border border-white/10 px-2 py-1 text-[0.65rem] uppercase tracking-[0.16em] text-slate-500">
                {{ cmd.mode }}
              </span>
            </div>
            <pre class="overflow-x-auto rounded-xl bg-black/40 p-3 text-xs leading-5 text-cyan-100"><code>{{ cmd.command }}</code></pre>
          </div>
        </div>
      </div>

      <div class="console-card">
        <div class="section-kicker">{{ $t('evidence.operatorKicker') }}</div>
        <h3 class="section-title">{{ $t('evidence.operatorTitle') }}</h3>
        <div class="mt-6 space-y-4">
          <div v-for="note in operatorNotes" :key="note.titleKey" class="rounded-2xl border border-amber-300/15 bg-amber-400/5 p-4">
            <div class="flex items-start gap-3">
              <span class="mt-1 status-dot bg-amber-300" />
              <div>
                <h4 class="text-sm font-semibold text-amber-100">{{ $t(note.titleKey) }}</h4>
                <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t(note.bodyKey) }}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
const tags = [
  'evidence.tags.chain',
  'evidence.tags.anchor',
  'evidence.tags.signatures',
  'evidence.tags.objectLock'
]

const contracts = [
  {
    labelKey: 'evidence.contracts.db.label',
    detailKey: 'evidence.contracts.db.detail',
    code: 'W2',
    badgeClass: 'bg-cyan-400/10 text-cyan-100'
  },
  {
    labelKey: 'evidence.contracts.external.label',
    detailKey: 'evidence.contracts.external.detail',
    code: 'W3-W8',
    badgeClass: 'bg-emerald-400/10 text-emerald-100'
  },
  {
    labelKey: 'evidence.contracts.bundle.label',
    detailKey: 'evidence.contracts.bundle.detail',
    code: 'W5/T3',
    badgeClass: 'bg-amber-400/10 text-amber-100'
  }
]

const controls = [
  {
    track: 'W2',
    titleKey: 'evidence.controls.chain.title',
    bodyKey: 'evidence.controls.chain.body',
    artifactKey: 'evidence.controls.chain.artifact',
    dotClass: 'bg-cyan-300'
  },
  {
    track: 'W3/W4',
    titleKey: 'evidence.controls.anchors.title',
    bodyKey: 'evidence.controls.anchors.body',
    artifactKey: 'evidence.controls.anchors.artifact',
    dotClass: 'bg-emerald-300'
  },
  {
    track: 'W8',
    titleKey: 'evidence.controls.sinks.title',
    bodyKey: 'evidence.controls.sinks.body',
    artifactKey: 'evidence.controls.sinks.artifact',
    dotClass: 'bg-sky-300'
  },
  {
    track: 'O4',
    titleKey: 'evidence.controls.objectLock.title',
    bodyKey: 'evidence.controls.objectLock.body',
    artifactKey: 'evidence.controls.objectLock.artifact',
    dotClass: 'bg-amber-300'
  },
  {
    track: 'W5/T3',
    titleKey: 'evidence.controls.bundle.title',
    bodyKey: 'evidence.controls.bundle.body',
    artifactKey: 'evidence.controls.bundle.artifact',
    dotClass: 'bg-purple-300'
  },
  {
    track: 'PROD1',
    titleKey: 'evidence.controls.validation.title',
    bodyKey: 'evidence.controls.validation.body',
    artifactKey: 'evidence.controls.validation.artifact',
    dotClass: 'bg-red-300'
  }
]

const pipeline = [
  { code: 'PG', titleKey: 'evidence.pipeline.rows.title', bodyKey: 'evidence.pipeline.rows.body' },
  { code: 'HMAC', titleKey: 'evidence.pipeline.chain.title', bodyKey: 'evidence.pipeline.chain.body' },
  { code: 'MERKLE', titleKey: 'evidence.pipeline.merkle.title', bodyKey: 'evidence.pipeline.merkle.body' },
  { code: 'ED25519', titleKey: 'evidence.pipeline.sign.title', bodyKey: 'evidence.pipeline.sign.body' },
  { code: 'SINK', titleKey: 'evidence.pipeline.sink.title', bodyKey: 'evidence.pipeline.sink.body' },
  { code: 'BUNDLE', titleKey: 'evidence.pipeline.bundle.title', bodyKey: 'evidence.pipeline.bundle.body' }
]

const commands = [
  {
    titleKey: 'evidence.commands.verifyBundle',
    mode: 'offline',
    command: 'audit-verify --bundle ./evidence_bundle.zip --verbose'
  },
  {
    titleKey: 'evidence.commands.exportTenant',
    mode: 'export',
    command: 'audit-export-evidence --org-id <uuid> --output ./tenant_bundle --zip'
  },
  {
    titleKey: 'evidence.commands.retention',
    mode: 's3',
    command: 'audit-evidence-report --bucket <bucket> --require-lock --min-retention-days 90'
  },
  {
    titleKey: 'evidence.commands.prodValidate',
    mode: 'prod',
    command: 'shadowai-prod-validate --evidence-bundle ./bundle.zip --bucket <bucket> --require-object-lock'
  }
]

const operatorNotes = [
  {
    titleKey: 'evidence.notes.notLive.title',
    bodyKey: 'evidence.notes.notLive.body'
  },
  {
    titleKey: 'evidence.notes.independentSink.title',
    bodyKey: 'evidence.notes.independentSink.body'
  },
  {
    titleKey: 'evidence.notes.restoreDrill.title',
    bodyKey: 'evidence.notes.restoreDrill.body'
  }
]
</script>
