<template>
  <section class="console-card">
    <div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <div class="section-kicker">{{ $t('tenants.manage.orgsKicker') }}</div>
        <h3 class="section-title">{{ $t('tenants.manage.orgsTitle') }}</h3>
        <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t('tenants.manage.orgsBody') }}</p>
      </div>
      <button
        v-if="canCreate"
        type="button"
        class="rounded-2xl border border-cyan-200/25 bg-cyan-200/10 px-4 py-2 text-sm font-semibold text-cyan-100 hover:bg-cyan-200/15"
        @click="$emit('toggle-create')"
      >
        {{ showCreate ? $t('common.cancel') : $t('tenants.manage.createOrg') }}
      </button>
    </div>

    <form v-if="showCreate" class="mt-5 grid gap-3 rounded-2xl border border-white/10 bg-slate-950/60 p-4 md:grid-cols-[1fr_0.8fr_auto]" @submit.prevent="$emit('create')">
      <input
        :value="draft.name"
        type="text"
        required
        class="tenant-input"
        :placeholder="$t('tenants.manage.name')"
        @input="$emit('update:draft', { ...draft, name: ($event.target as HTMLInputElement).value })"
      />
      <input
        :value="draft.slug"
        type="text"
        required
        class="tenant-input"
        :placeholder="$t('tenants.manage.slug')"
        @input="$emit('update:draft', { ...draft, slug: ($event.target as HTMLInputElement).value })"
      />
      <button type="submit" class="rounded-xl bg-emerald-400 px-4 py-2 text-sm font-bold text-slate-950 hover:bg-emerald-300">
        {{ $t('tenants.manage.save') }}
      </button>
    </form>

    <div v-if="loading" class="mt-6 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
      {{ $t('common.loading') }}
    </div>
    <div v-else-if="orgs.length === 0" class="mt-6 rounded-2xl border border-amber-200/15 bg-amber-200/10 p-4 text-sm text-amber-100">
      {{ $t('tenants.manage.empty') }}
    </div>
    <div v-else class="mt-6 space-y-2">
      <button
        v-for="org in orgs"
        :key="org.id"
        type="button"
        class="w-full rounded-2xl border p-4 text-left transition-colors"
        :class="org.id === selectedOrgId ? 'border-cyan-200/35 bg-cyan-200/10' : 'border-white/10 bg-white/[0.035] hover:border-white/20'"
        @click="$emit('select', org.id)"
      >
        <div class="flex items-start justify-between gap-4">
          <div>
            <div class="font-semibold text-white">{{ org.name }}</div>
            <div class="mt-1 font-mono text-xs text-slate-500">{{ org.id }}</div>
          </div>
          <span class="rounded-full px-3 py-1 text-xs font-semibold" :class="org.is_active ? 'bg-emerald-300/10 text-emerald-200' : 'bg-red-300/10 text-red-200'">
            {{ org.is_active ? $t('tenants.manage.active') : $t('tenants.manage.inactive') }}
          </span>
        </div>
        <div class="mt-3 text-xs uppercase tracking-[0.2em] text-slate-500">{{ org.slug }}</div>
      </button>
    </div>
  </section>
</template>

<script setup lang="ts">
import type { Organization } from '../../api/tenants'

defineProps<{
  orgs: Organization[]
  selectedOrgId: string
  loading: boolean
  canCreate: boolean
  showCreate: boolean
  draft: { name: string; slug: string }
}>()

defineEmits<{
  select: [orgID: string]
  create: []
  'toggle-create': []
  'update:draft': [draft: { name: string; slug: string }]
}>()
</script>
