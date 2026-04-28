<template>
  <div class="min-h-screen bg-dark-950 flex items-center justify-center p-4">
    <div class="w-full max-w-sm bg-dark-900 rounded-2xl p-8 border border-dark-700">
      <h1 class="text-2xl font-bold text-center text-primary-400 mb-2">{{ $t('auth.mfaVerifyTitle') }}</h1>
      <p class="text-center text-gray-500 text-sm mb-8">{{ $t('auth.mfaVerifyBody') }}</p>

      <form @submit.prevent="handleVerify" class="space-y-4">
        <div>
          <label class="block text-sm text-gray-400 mb-1">{{ $t('auth.mfaCode') }}</label>
          <input v-model="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="8" class="auth-input text-center tracking-[0.4em]" />
        </div>
        <p v-if="!authStore.pendingMFAToken" class="text-amber-300 text-sm">{{ $t('auth.mfaTokenMissing') }}</p>
        <p v-if="error" class="text-red-400 text-sm">{{ error }}</p>
        <button type="submit" :disabled="loading || !authStore.pendingMFAToken" class="auth-primary">
          {{ loading ? $t('auth.verifying') : $t('auth.verifyMfa') }}
        </button>
      </form>

      <p class="text-center text-sm text-gray-500 mt-5">
        <router-link to="/login" class="text-primary-400 hover:underline">{{ $t('auth.backToLogin') }}</router-link>
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../stores/auth'

const { t } = useI18n()
const router = useRouter()
const authStore = useAuthStore()
const code = ref('')
const error = ref('')
const loading = ref(false)

async function handleVerify() {
  loading.value = true
  error.value = ''
  try {
    await authStore.completeMFA(code.value)
    router.push('/dashboard')
  } catch (e: any) {
    error.value = e.response?.data?.error || t('auth.mfaInvalid')
  } finally {
    loading.value = false
  }
}
</script>
