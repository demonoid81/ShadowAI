<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 max-w-5xl">
        <div class="mb-5 flex flex-wrap gap-2">
          <span class="tag-chip">admin_event_logs</span>
          <span class="tag-chip">source_org_id</span>
          <span class="tag-chip">target_org_id</span>
        </div>
        <h2 class="text-4xl font-semibold tracking-tight text-white sm:text-5xl">{{ $t('adminEvents.heroTitle') }}</h2>
        <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">{{ $t('adminEvents.heroSubtitle') }}</p>
      </div>
    </section>

    <div v-if="error" class="rounded-3xl border border-red-300/20 bg-red-400/10 p-4 text-sm text-red-100">{{ error }}</div>

    <AdminEventsTable
      :events="events"
      :filters="filters"
      :loading="loading"
      @update:filters="Object.assign(filters, $event)"
      @load="reload"
    />

    <div class="flex justify-between items-center text-sm text-slate-500">
      <span>{{ $t('adminEvents.total', { total }) }}</span>
      <div class="flex gap-2">
        <button type="button" class="rounded-xl bg-slate-800 px-3 py-1 disabled:opacity-50" :disabled="offset === 0" @click="prevPage">{{ $t('audit.prev') }}</button>
        <button type="button" class="rounded-xl bg-slate-800 px-3 py-1 disabled:opacity-50" :disabled="offset + limit >= total" @click="nextPage">{{ $t('audit.next') }}</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import AdminEventsTable from '../components/legal/AdminEventsTable.vue'
import { useAdminEvents } from '../composables/useAdminEvents'

const { events, total, loading, error, offset, limit, filters, load, nextPage, prevPage } = useAdminEvents()

function reload() {
  offset.value = 0
  load()
}

onMounted(load)
</script>
