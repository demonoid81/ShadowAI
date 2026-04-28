<template>
  <section class="console-card">
    <div class="section-kicker">{{ $t('tenants.manage.detailKicker') }}</div>
    <h3 class="section-title">{{ org ? org.name : $t('tenants.manage.noSelection') }}</h3>

    <div v-if="!org" class="mt-6 rounded-2xl border border-white/10 bg-white/[0.03] p-5 text-sm text-slate-400">
      {{ $t('tenants.manage.selectOrg') }}
    </div>

    <div v-else class="mt-6 space-y-6">
      <form class="grid gap-3 md:grid-cols-2" @submit.prevent="$emit('save-org')">
        <label class="tenant-label">
          {{ $t('tenants.manage.name') }}
          <input
            :value="draft.name"
            :disabled="!canEdit"
            class="tenant-input mt-2"
            @input="$emit('update:draft', { ...draft, name: ($event.target as HTMLInputElement).value })"
          />
        </label>
        <label class="tenant-label">
          {{ $t('tenants.manage.slug') }}
          <input
            :value="draft.slug"
            :disabled="!canEdit"
            class="tenant-input mt-2"
            @input="$emit('update:draft', { ...draft, slug: ($event.target as HTMLInputElement).value })"
          />
        </label>
        <label class="flex items-center gap-3 rounded-2xl border border-white/10 bg-slate-950/50 px-4 py-3 text-sm text-slate-300">
          <input
            :checked="draft.is_active"
            :disabled="!canEdit"
            type="checkbox"
            class="h-4 w-4 accent-cyan-300"
            @change="$emit('update:draft', { ...draft, is_active: ($event.target as HTMLInputElement).checked })"
          />
          {{ $t('tenants.manage.active') }}
        </label>
        <div class="flex items-end justify-end">
          <button
            type="submit"
            :disabled="!canEdit || saving"
            class="rounded-xl bg-cyan-300 px-4 py-2 text-sm font-bold text-slate-950 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {{ saving ? $t('common.saving') : $t('tenants.manage.save') }}
          </button>
        </div>
      </form>

      <div class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
        <div class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('tenants.manage.metadata') }}</div>
        <dl class="mt-4 grid gap-3 text-sm md:grid-cols-2">
          <div>
            <dt class="text-slate-500">{{ $t('tenants.manage.orgId') }}</dt>
            <dd class="mt-1 break-all font-mono text-slate-300">{{ org.id }}</dd>
          </div>
          <div>
            <dt class="text-slate-500">{{ $t('tenants.manage.updated') }}</dt>
            <dd class="mt-1 text-slate-300">{{ formatDate(org.updated_at) }}</dd>
          </div>
        </dl>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import type { Organization } from '../../api/tenants'

defineProps<{
  org: Organization | null
  draft: { name: string; slug: string; is_active: boolean }
  canEdit: boolean
  saving: boolean
}>()

defineEmits<{
  'save-org': []
  'update:draft': [draft: { name: string; slug: string; is_active: boolean }]
}>()

function formatDate(value: string) {
  return value ? new Date(value).toLocaleString() : '—'
}
</script>
