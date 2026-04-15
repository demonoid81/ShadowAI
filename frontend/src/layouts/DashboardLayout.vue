<template>
  <div class="flex h-screen bg-dark-950 text-gray-100">
    <aside class="w-64 bg-dark-900 border-r border-dark-700 flex flex-col">
      <div class="p-6">
        <h1 class="text-xl font-bold text-primary-400">{{ $t('app.title') }}</h1>
        <p class="text-xs text-gray-500 mt-1">{{ $t('app.subtitle') }}</p>
      </div>
      <nav class="flex-1 px-4 space-y-1">
        <router-link v-for="item in nav" :key="item.to" :to="item.to"
          class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors"
          :class="$route.path === item.to ? 'bg-primary-600/20 text-primary-400' : 'text-gray-400 hover:text-gray-200 hover:bg-dark-800'">
          <span>{{ item.icon }}</span>
          <span>{{ $t(item.labelKey) }}</span>
        </router-link>
      </nav>
      <div class="p-4 border-t border-dark-700 space-y-2">
        <div class="flex items-center gap-2 px-3">
          <span class="text-xs text-gray-500">{{ $t('common.language') }}:</span>
          <button v-for="lang in ['ru', 'en']" :key="lang" @click="setLocale(lang)"
            class="px-2 py-0.5 text-xs rounded transition-colors"
            :class="currentLocale === lang ? 'bg-primary-600 text-white' : 'text-gray-400 hover:text-gray-200'">
            {{ lang.toUpperCase() }}
          </button>
        </div>
        <button @click="logout" class="w-full px-3 py-2 text-sm text-gray-400 hover:text-red-400 rounded-lg hover:bg-dark-800 transition-colors">
          {{ $t('nav.logout') }}
        </button>
      </div>
    </aside>
    <main class="flex-1 overflow-auto p-8">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const authStore = useAuthStore()
const { locale } = useI18n()

const currentLocale = computed(() => locale.value)

const nav = [
  { to: '/dashboard', icon: '\u{1F4CA}', labelKey: 'nav.dashboard' },
  { to: '/audit', icon: '\u{1F4CB}', labelKey: 'nav.audit' },
  { to: '/policies', icon: '\u{1F6E1}\u{FE0F}', labelKey: 'nav.policies' },
  { to: '/budget', icon: '\u{1F4B0}', labelKey: 'nav.budget' },
  { to: '/users', icon: '\u{1F465}', labelKey: 'nav.users' },
  { to: '/providers', icon: '\u{1F310}', labelKey: 'nav.providers' },
  { to: '/firewall', icon: '\u{1F525}', labelKey: 'nav.firewall' },
  { to: '/internal-db', icon: '\u{1F5C4}\u{FE0F}', labelKey: 'nav.internalDb' }
]

function setLocale(lang: string) {
  locale.value = lang
  localStorage.setItem('locale', lang)
}

function logout() {
  authStore.logout()
  router.push('/login')
}
</script>
