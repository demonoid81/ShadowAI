<template>
  <div class="min-h-screen overflow-hidden bg-console text-slate-100">
    <div class="pointer-events-none fixed inset-0 opacity-80">
      <div class="absolute left-[-12rem] top-[-10rem] h-96 w-96 rounded-full bg-cyan-500/10 blur-3xl" />
      <div class="absolute right-[-10rem] top-1/3 h-[28rem] w-[28rem] rounded-full bg-emerald-500/10 blur-3xl" />
      <div class="absolute bottom-[-18rem] left-1/3 h-[32rem] w-[32rem] rounded-full bg-amber-500/5 blur-3xl" />
    </div>

    <div class="relative flex min-h-screen">
      <aside class="hidden w-80 shrink-0 border-r border-white/10 bg-slate-950/85 backdrop-blur-2xl lg:flex lg:flex-col">
        <div class="border-b border-white/10 p-6">
          <div class="flex items-center gap-4">
            <div class="brand-mark">SA</div>
            <div>
              <h1 class="text-lg font-semibold tracking-[0.34em] text-white">{{ $t('app.title') }}</h1>
              <p class="mt-1 text-xs uppercase tracking-[0.22em] text-cyan-200/70">{{ $t('app.subtitle') }}</p>
            </div>
          </div>

          <div class="mt-6 rounded-2xl border border-emerald-400/20 bg-emerald-400/10 p-4">
            <div class="flex items-center justify-between">
              <span class="text-xs uppercase tracking-[0.22em] text-emerald-200/80">{{ $t('layout.posture') }}</span>
              <span class="status-dot bg-emerald-300" />
            </div>
            <p class="mt-2 text-sm font-medium text-white">{{ $t('layout.postureReady') }}</p>
            <p class="mt-1 text-xs leading-5 text-emerald-100/65">{{ $t('layout.postureText') }}</p>
          </div>
        </div>

        <nav class="flex-1 overflow-y-auto px-4 py-5">
          <section v-for="group in navGroups" :key="group.key" class="mb-7">
            <div class="mb-2 px-3 text-[0.68rem] font-semibold uppercase tracking-[0.24em] text-slate-500">
              {{ $t(group.labelKey) }}
            </div>
            <div class="space-y-1">
              <router-link
                v-for="item in group.items"
                :key="item.to"
                :to="item.to"
                class="group flex items-center gap-3 rounded-2xl px-3 py-3 text-sm transition-all duration-200"
                :class="isActive(item.to)
                  ? 'border border-cyan-300/25 bg-cyan-300/10 text-white shadow-[0_0_24px_rgba(34,211,238,0.10)]'
                  : 'border border-transparent text-slate-400 hover:border-white/10 hover:bg-white/[0.04] hover:text-slate-100'"
              >
                <span
                  class="grid h-9 w-9 place-items-center rounded-xl border text-[0.62rem] font-bold tracking-[0.18em]"
                  :class="isActive(item.to)
                    ? 'border-cyan-200/30 bg-cyan-200/15 text-cyan-100'
                    : 'border-white/10 bg-white/[0.03] text-slate-500 group-hover:text-slate-200'"
                >
                  {{ item.code }}
                </span>
                <span class="flex-1">
                  <span class="block font-medium">{{ $t(item.labelKey) }}</span>
                  <span class="mt-0.5 block text-xs text-slate-500">{{ $t(item.captionKey) }}</span>
                </span>
              </router-link>
            </div>
          </section>
        </nav>

        <div class="border-t border-white/10 p-4">
          <div class="mb-3 flex items-center justify-between rounded-2xl border border-white/10 bg-white/[0.03] px-3 py-2">
            <span class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ $t('common.language') }}</span>
            <div class="flex gap-1">
              <button
                v-for="lang in ['ru', 'en']"
                :key="lang"
                @click="setLocale(lang)"
                class="rounded-lg px-2 py-1 text-xs font-semibold transition-colors"
                :class="currentLocale === lang ? 'bg-white text-slate-950' : 'text-slate-400 hover:bg-white/10 hover:text-white'"
              >
                {{ lang.toUpperCase() }}
              </button>
            </div>
          </div>
          <button
            @click="logout"
            class="w-full rounded-2xl border border-red-300/10 px-4 py-3 text-left text-sm text-red-200/80 transition-colors hover:border-red-300/30 hover:bg-red-400/10 hover:text-red-100"
          >
            {{ $t('nav.logout') }}
          </button>
        </div>
      </aside>

      <main class="relative flex-1 overflow-y-auto">
        <header class="sticky top-0 z-20 border-b border-white/10 bg-slate-950/70 px-4 py-4 backdrop-blur-2xl sm:px-6 lg:px-10">
          <div class="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <div class="text-xs uppercase tracking-[0.28em] text-cyan-200/70">{{ $t('layout.console') }}</div>
              <div class="mt-1 text-2xl font-semibold text-white">{{ $t(routeTitleKey) }}</div>
            </div>
            <div class="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap">
              <div v-for="signal in trustSignals" :key="signal.key" class="trust-pill">
                <span class="status-dot" :class="signal.color" />
                <span>{{ $t(signal.labelKey) }}</span>
              </div>
            </div>
          </div>
          <div class="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:hidden">
            <router-link
              v-for="item in mobileNav"
              :key="item.to"
              :to="item.to"
              class="rounded-2xl border px-3 py-2 text-sm transition-colors"
              :class="isActive(item.to)
                ? 'border-cyan-300/30 bg-cyan-300/10 text-cyan-100'
                : 'border-white/10 bg-white/[0.03] text-slate-400 hover:text-white'"
            >
              <span class="mr-2 text-xs font-bold tracking-[0.18em] text-slate-500">{{ item.code }}</span>
              {{ $t(item.labelKey) }}
            </router-link>
          </div>
        </header>

        <div class="p-4 sm:p-6 lg:p-10">
          <router-view />
        </div>
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const { locale } = useI18n()

const currentLocale = computed(() => locale.value)

const navGroups = computed(() => {
  const groups = [
    {
      key: 'observe',
      labelKey: 'layout.groups.observe',
      items: [
        { to: '/dashboard', code: 'OV', labelKey: 'nav.dashboard', captionKey: 'layout.navCaptions.dashboard' },
        { to: '/audit', code: 'AU', labelKey: 'nav.audit', captionKey: 'layout.navCaptions.audit', adminOnly: true }
      ]
    },
    {
      key: 'govern',
      labelKey: 'layout.groups.govern',
      items: [
        { to: '/policies', code: 'GP', labelKey: 'nav.policies', captionKey: 'layout.navCaptions.policies', adminOnly: true },
        { to: '/budget', code: 'BC', labelKey: 'nav.budget', captionKey: 'layout.navCaptions.budget' },
        { to: '/providers', code: 'VR', labelKey: 'nav.providers', captionKey: 'layout.navCaptions.providers' },
        { to: '/tenants', code: 'TN', labelKey: 'nav.tenants', captionKey: 'layout.navCaptions.tenants', adminOnly: true }
      ]
    },
    {
      key: 'protect',
      labelKey: 'layout.groups.protect',
      items: [
        { to: '/firewall', code: 'FW', labelKey: 'nav.firewall', captionKey: 'layout.navCaptions.firewall', adminOnly: true },
        { to: '/internal-db', code: 'DB', labelKey: 'nav.internalDb', captionKey: 'layout.navCaptions.internalDb' }
      ]
    },
    {
      key: 'evidence',
      labelKey: 'layout.groups.evidence',
      items: [
        { to: '/evidence', code: 'EV', labelKey: 'nav.evidence', captionKey: 'layout.navCaptions.evidence', adminOnly: true },
        { to: '/compliance', code: 'CO', labelKey: 'nav.compliance', captionKey: 'layout.navCaptions.compliance', adminOnly: true }
      ]
    },
    {
      key: 'operate',
      labelKey: 'layout.groups.operate',
      items: [
        { to: '/users', code: 'ID', labelKey: 'nav.users', captionKey: 'layout.navCaptions.users', adminOnly: true },
        { to: '/security', code: 'SC', labelKey: 'nav.security', captionKey: 'layout.navCaptions.security' },
        { to: '/operations', code: 'OP', labelKey: 'nav.operations', captionKey: 'layout.navCaptions.operations', adminOnly: true },
        { to: '/settings', code: 'ST', labelKey: 'nav.settings', captionKey: 'layout.navCaptions.settings', adminOnly: true }
      ]
    }
  ]

  return groups
    .map(group => ({ ...group, items: group.items.filter(item => !item.adminOnly || authStore.isAdmin) }))
    .filter(group => group.items.length > 0)
})

const routeTitleKey = computed(() => {
  const current = navGroups.value.flatMap(group => group.items).find(item => item.to === route.path)
  return current?.labelKey ?? 'nav.dashboard'
})

const mobileNav = computed(() => navGroups.value.flatMap(group => group.items))

const trustSignals = [
  { key: 'tenant', labelKey: 'layout.signals.tenant', color: 'bg-cyan-300' },
  { key: 'worm', labelKey: 'layout.signals.worm', color: 'bg-emerald-300' },
  { key: 'byok', labelKey: 'layout.signals.byok', color: 'bg-amber-300' },
  { key: 'prod', labelKey: 'layout.signals.prod', color: 'bg-sky-300' }
]

function isActive(path: string) {
  return route.path === path
}

function setLocale(lang: string) {
  locale.value = lang
  localStorage.setItem('locale', lang)
}

function logout() {
  authStore.logout()
  router.push('/login')
}
</script>
