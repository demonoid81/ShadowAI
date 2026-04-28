<template>
  <div class="min-h-screen bg-dark-950 flex items-center justify-center p-4">
    <div class="w-full max-w-md bg-dark-900 rounded-2xl p-8 border border-dark-700">
      <h1 class="text-2xl font-bold text-center text-primary-400 mb-2">{{ $t('app.title') }}</h1>
      <p class="text-center text-gray-500 text-sm mb-8">{{ $t('app.subtitle') }}</p>

      <form v-if="mode === 'password'" @submit.prevent="handleLogin" class="space-y-4">
        <div>
          <label class="block text-sm text-gray-400 mb-1">{{ $t('auth.email') }}</label>
          <input v-model="email" type="email" required class="auth-input" />
        </div>
        <div>
          <label class="block text-sm text-gray-400 mb-1">{{ $t('auth.password') }}</label>
          <input v-model="password" type="password" required class="auth-input" />
        </div>
        <p v-if="error" class="text-red-400 text-sm">{{ error }}</p>
        <button type="submit" :disabled="loading" class="auth-primary">
          {{ loading ? $t('auth.signingIn') : $t('auth.signIn') }}
        </button>
      </form>

      <form v-else @submit.prevent="handleBreakGlass" class="space-y-4">
        <div class="rounded-xl border border-red-300/20 bg-red-400/10 p-4 text-sm leading-6 text-red-100">
          {{ $t('auth.breakGlassWarning') }}
        </div>
        <div>
          <label class="block text-sm text-gray-400 mb-1">{{ $t('auth.breakGlassSecret') }}</label>
          <input v-model="breakGlassSecret" type="password" required class="auth-input" />
        </div>
        <p v-if="error" class="text-red-400 text-sm">{{ error }}</p>
        <button type="submit" :disabled="loading || !showBreakGlassWarning" class="auth-danger">
          {{ loading ? $t('auth.signingIn') : $t('auth.breakGlassSubmit') }}
        </button>
      </form>

      <div class="mt-6 grid gap-3">
        <a href="/api/auth/oidc/login" class="auth-secondary">
          {{ $t('auth.oidcLogin') }}
        </a>
        <button type="button" class="text-sm text-red-300 hover:text-red-200" @click="toggleMode">
          {{ mode === 'password' ? $t('auth.breakGlassLink') : $t('auth.normalLoginLink') }}
        </button>
      </div>

      <p class="text-center text-sm text-gray-500 mt-5">
        {{ $t('auth.noAccount') }}
        <router-link to="/register" class="text-primary-400 hover:underline">{{ $t('auth.register') }}</router-link>
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../stores/auth'
import { nextAuthDestination, shouldShowBreakGlassWarning } from '../utils/authFlow'

const { t } = useI18n()
const router = useRouter()
const authStore = useAuthStore()
const email = ref('')
const password = ref('')
const breakGlassSecret = ref('')
const error = ref('')
const loading = ref(false)
const mode = ref<'password' | 'break_glass'>('password')

const showBreakGlassWarning = computed(() => shouldShowBreakGlassWarning(breakGlassSecret.value))

function routeAfterLogin(mfaRequired: boolean) {
  const destination = nextAuthDestination(authStore.claims, mfaRequired)
  if (destination === 'mfa_verify') router.push('/mfa/verify')
  else if (destination === 'security_enrollment') router.push('/security')
  else router.push('/dashboard')
}

async function handleLogin() {
  loading.value = true
  error.value = ''
  try {
    const result = await authStore.login(email.value, password.value)
    routeAfterLogin('mfa_required' in result && result.mfa_required === true)
  } catch {
    error.value = t('auth.invalidCredentials')
  } finally {
    loading.value = false
  }
}

async function handleBreakGlass() {
  loading.value = true
  error.value = ''
  try {
    await authStore.breakGlass(breakGlassSecret.value)
    router.push('/dashboard')
  } catch (e: any) {
    error.value = e.response?.data?.error || t('auth.breakGlassError')
  } finally {
    loading.value = false
  }
}

function toggleMode() {
  mode.value = mode.value === 'password' ? 'break_glass' : 'password'
  error.value = ''
}
</script>
