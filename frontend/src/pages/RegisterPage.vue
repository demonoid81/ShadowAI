<template>
  <div class="min-h-screen bg-dark-950 flex items-center justify-center">
    <div class="w-full max-w-sm bg-dark-900 rounded-2xl p-8 border border-dark-700">
      <h1 class="text-2xl font-bold text-center text-primary-400 mb-2">{{ $t('app.title') }}</h1>
      <p class="text-center text-gray-500 text-sm mb-8">{{ $t('auth.register') }}</p>
      <form @submit.prevent="handleRegister" class="space-y-4">
        <div>
          <label class="block text-sm text-gray-400 mb-1">{{ $t('auth.email') }}</label>
          <input v-model="email" type="email" required
            class="w-full px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 focus:border-primary-500 focus:outline-none" />
        </div>
        <div>
          <label class="block text-sm text-gray-400 mb-1">{{ $t('auth.password') }}</label>
          <input v-model="password" type="password" required
            class="w-full px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 focus:border-primary-500 focus:outline-none" />
        </div>
        <div>
          <label class="block text-sm text-gray-400 mb-1">{{ $t('auth.role') }}</label>
          <select v-model="role"
            class="w-full px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 focus:border-primary-500 focus:outline-none">
            <option value="user">{{ $t('users.user') }}</option>
            <option value="analyst">{{ $t('users.analyst') }}</option>
            <option value="auditor">{{ $t('users.auditor') }}</option>
          </select>
        </div>
        <p v-if="error" class="text-red-400 text-sm">{{ error }}</p>
        <p v-if="success" class="text-green-400 text-sm">{{ success }}</p>
        <button type="submit" :disabled="loading"
          class="w-full py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white font-medium transition-colors disabled:opacity-50">
          {{ loading ? $t('auth.registering') : $t('auth.register') }}
        </button>
      </form>
      <p class="text-center text-sm text-gray-500 mt-4">
        {{ $t('auth.hasAccount') }}
        <router-link to="/login" class="text-primary-400 hover:underline">{{ $t('auth.signIn') }}</router-link>
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '../api/client'

const { t } = useI18n()
const email = ref('')
const password = ref('')
const role = ref('user')
const error = ref('')
const success = ref('')
const loading = ref(false)

async function handleRegister() {
  loading.value = true
  error.value = ''
  success.value = ''
  try {
    await api.post('/auth/register', { email: email.value, password: password.value, role: role.value })
    success.value = t('auth.registerSuccess')
    email.value = ''
    password.value = ''
  } catch (e: any) {
    error.value = e.response?.data?.error || t('auth.registerError')
  } finally {
    loading.value = false
  }
}
</script>
