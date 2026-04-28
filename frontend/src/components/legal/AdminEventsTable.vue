<template>
  <section class="console-card">
    <div class="section-kicker">{{ $t('adminEvents.kicker') }}</div>
    <h3 class="section-title">{{ $t('adminEvents.title') }}</h3>

    <form class="mt-5 grid gap-3 md:grid-cols-5" @submit.prevent="$emit('load')">
      <input :value="filters.actor_user_id" class="tenant-input" :placeholder="$t('adminEvents.actor')" @input="patch('actor_user_id', ($event.target as HTMLInputElement).value)" />
      <input :value="filters.resource" class="tenant-input" :placeholder="$t('adminEvents.resource')" @input="patch('resource', ($event.target as HTMLInputElement).value)" />
      <input :value="filters.action" class="tenant-input" :placeholder="$t('adminEvents.action')" @input="patch('action', ($event.target as HTMLInputElement).value)" />
      <input :value="filters.org" class="tenant-input" :placeholder="$t('adminEvents.orgFilter')" @input="patch('org', ($event.target as HTMLInputElement).value)" />
      <select :value="filters.success" class="tenant-input" @change="patch('success', ($event.target as HTMLSelectElement).value)">
        <option value="">{{ $t('adminEvents.anyStatus') }}</option>
        <option value="true">{{ $t('adminEvents.success') }}</option>
        <option value="false">{{ $t('adminEvents.failure') }}</option>
      </select>
      <button type="submit" class="rounded-xl bg-cyan-300 px-4 py-2 text-sm font-bold text-slate-950 md:col-span-5">
        {{ $t('adminEvents.applyFilters') }}
      </button>
    </form>
    <p class="mt-2 text-xs text-slate-500">{{ $t('adminEvents.pageFilterHint') }}</p>

    <div v-if="loading" class="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">{{ $t('common.loading') }}</div>
    <div v-else class="mt-5 overflow-hidden rounded-2xl border border-white/10">
      <table class="w-full text-sm">
        <thead class="bg-white/[0.03] text-left text-xs uppercase tracking-[0.2em] text-slate-500">
          <tr>
            <th class="px-4 py-3">{{ $t('adminEvents.created') }}</th>
            <th class="px-4 py-3">{{ $t('adminEvents.action') }}</th>
            <th class="px-4 py-3">{{ $t('adminEvents.resource') }}</th>
            <th class="px-4 py-3">{{ $t('adminEvents.orgContext') }}</th>
            <th class="px-4 py-3">{{ $t('adminEvents.metadata') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="event in visibleEvents" :key="event.id" class="border-t border-white/10 align-top">
            <td class="px-4 py-3 text-xs text-slate-500">{{ formatDate(event.created_at) }}</td>
            <td class="px-4 py-3">
              <div class="font-semibold text-white">{{ event.action }}</div>
              <div class="mt-1 text-xs" :class="event.success ? 'text-emerald-300' : 'text-red-300'">{{ event.status_code }}</div>
            </td>
            <td class="px-4 py-3 text-slate-300">{{ event.resource }}</td>
            <td class="px-4 py-3 font-mono text-xs text-slate-500">
              <div>org: {{ event.org_id || 'global' }}</div>
              <div>source: {{ event.source_org_id || '—' }}</div>
              <div>target: {{ event.target_org_id || '—' }}</div>
            </td>
            <td class="px-4 py-3">
              <pre class="max-h-32 overflow-auto rounded-xl bg-black/30 p-2 text-xs text-slate-400"><code>{{ metadata(event.metadata_json) }}</code></pre>
            </td>
          </tr>
          <tr v-if="visibleEvents.length === 0">
            <td colspan="5" class="px-4 py-5 text-center text-slate-500">{{ $t('adminEvents.empty') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { AdminEvent } from '../../api/legal'
import { safeMetadataPreview } from '../../utils/legalHoldUi'

const props = defineProps<{
  events: AdminEvent[]
  filters: { actor_user_id: string; resource: string; action: string; org: string; success: string }
  loading: boolean
}>()

const emit = defineEmits<{
  'update:filters': [filters: { actor_user_id: string; resource: string; action: string; org: string; success: string }]
  load: []
}>()

const visibleEvents = computed(() => {
  return props.events.filter(event => {
    if (props.filters.success && String(event.success) !== props.filters.success) return false
    if (!props.filters.org) return true
    const needle = props.filters.org.toLowerCase()
    return [event.org_id, event.source_org_id, event.target_org_id].some(value => (value ?? '').toLowerCase().includes(needle))
  })
})

function patch(key: keyof typeof props.filters, value: string) {
  emit('update:filters', { ...props.filters, [key]: value })
}

function metadata(raw?: string) {
  return safeMetadataPreview(raw ?? '')
}

function formatDate(value: string) {
  return value ? new Date(value).toLocaleString() : '—'
}
</script>
