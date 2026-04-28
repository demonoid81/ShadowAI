<template>
  <section class="console-card">
    <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div>
        <div class="section-kicker">{{ $t('tenants.scim.kicker') }}</div>
        <h3 class="section-title">{{ $t('tenants.scim.title') }}</h3>
        <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t('tenants.scim.body') }}</p>
      </div>
      <form v-if="orgId" class="flex gap-2" @submit.prevent="$emit('create-token')">
        <input
          :value="label"
          type="text"
          class="tenant-input min-w-0"
          :placeholder="$t('tenants.scim.label')"
          @input="$emit('update:label', ($event.target as HTMLInputElement).value)"
        />
        <button type="submit" :disabled="saving" class="rounded-xl bg-emerald-300 px-4 py-2 text-sm font-bold text-slate-950 disabled:opacity-50">
          {{ $t('tenants.scim.create') }}
        </button>
      </form>
    </div>

    <div v-if="plainToken" class="mt-5 rounded-2xl border border-amber-200/25 bg-amber-200/10 p-4">
      <div class="text-sm font-semibold text-amber-100">{{ $t('tenants.scim.oneTimeTitle') }}</div>
      <p class="mt-2 text-sm leading-6 text-amber-100/80">{{ $t('tenants.scim.oneTimeBody') }}</p>
      <pre class="mt-3 overflow-x-auto rounded-xl bg-black/40 p-3 text-xs text-amber-50"><code>{{ plainToken }}</code></pre>
      <button type="button" class="mt-3 text-xs font-semibold uppercase tracking-[0.18em] text-amber-100 hover:text-white" @click="$emit('clear-plain')">
        {{ $t('tenants.scim.clearPlain') }}
      </button>
    </div>

    <div v-if="loading" class="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
      {{ $t('common.loading') }}
    </div>
    <div v-else-if="tokens.length === 0" class="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
      {{ $t('tenants.scim.empty') }}
    </div>
    <div v-else class="mt-5 overflow-hidden rounded-2xl border border-white/10">
      <table class="w-full text-sm">
        <thead class="bg-white/[0.03] text-left text-xs uppercase tracking-[0.2em] text-slate-500">
          <tr>
            <th class="px-4 py-3">{{ $t('tenants.scim.label') }}</th>
            <th class="px-4 py-3">{{ $t('tenants.scim.created') }}</th>
            <th class="px-4 py-3">{{ $t('tenants.scim.lastUsed') }}</th>
            <th class="px-4 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="token in tokens" :key="token.id" class="border-t border-white/10">
            <td class="px-4 py-3 text-slate-200">{{ token.label || $t('tenants.scim.unlabeled') }}</td>
            <td class="px-4 py-3 text-slate-500">{{ formatDate(token.created_at) }}</td>
            <td class="px-4 py-3 text-slate-500">{{ token.last_used_at ? formatDate(token.last_used_at) : $t('tenants.scim.never') }}</td>
            <td class="px-4 py-3 text-right">
              <button type="button" class="text-xs font-semibold text-red-200 hover:text-red-100" @click="$emit('revoke-token', token.id)">
                {{ $t('tenants.scim.revoke') }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup lang="ts">
import type { SCIMToken } from '../../api/tenants'

defineProps<{
  orgId: string
  tokens: SCIMToken[]
  label: string
  plainToken: string
  loading: boolean
  saving: boolean
}>()

defineEmits<{
  'update:label': [label: string]
  'create-token': []
  'revoke-token': [tokenID: string]
  'clear-plain': []
}>()

function formatDate(value: string) {
  return value ? new Date(value).toLocaleString() : '—'
}
</script>
