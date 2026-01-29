<template>
  <div class="flex h-screen bg-dark-950 text-gray-100">
    <aside class="w-64 bg-dark-900 border-r border-dark-700 flex flex-col">
      <div class="p-6">
        <h1 class="text-xl font-bold text-primary-400">ShadowAI</h1>
        <p class="text-xs text-gray-500 mt-1">AI Control Plane</p>
      </div>
      <nav class="flex-1 px-4 space-y-1">
        <router-link v-for="item in nav" :key="item.to" :to="item.to"
          class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors"
          :class="$route.path === item.to ? 'bg-primary-600/20 text-primary-400' : 'text-gray-400 hover:text-gray-200 hover:bg-dark-800'">
          <span>{{ item.icon }}</span>
          <span>{{ item.label }}</span>
        </router-link>
      </nav>
      <div class="p-4 border-t border-dark-700">
        <button @click="logout" class="w-full px-3 py-2 text-sm text-gray-400 hover:text-red-400 rounded-lg hover:bg-dark-800 transition-colors">
          Logout
        </button>
      </div>
    </aside>
    <main class="flex-1 overflow-auto p-8">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const nav = [
  { to: '/dashboard', icon: '📊', label: 'Dashboard' },
  { to: '/audit', icon: '📋', label: 'Audit Logs' },
  { to: '/policies', icon: '🛡️', label: 'Policies' },
  { to: '/budget', icon: '💰', label: 'Budget' },
  { to: '/users', icon: '👥', label: 'Users' }
]

function logout() {
  authStore.logout()
  router.push('/login')
}
</script>
