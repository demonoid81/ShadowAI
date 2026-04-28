<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 max-w-4xl">
        <div class="mb-5 flex flex-wrap gap-2">
          <span class="tag-chip">MFA</span>
          <span class="tag-chip">OIDC</span>
          <span class="tag-chip">API key</span>
          <span v-if="claims?.break_glass" class="tag-chip border-red-200/30 bg-red-300/10 text-red-100">break-glass</span>
        </div>
        <h2 class="text-4xl font-semibold tracking-tight text-white sm:text-5xl">{{ $t('security.title') }}</h2>
        <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">{{ $t('security.subtitle') }}</p>
      </div>
    </section>

    <div v-if="message" class="rounded-3xl border border-emerald-300/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">{{ message }}</div>
    <div v-if="error" class="rounded-3xl border border-red-300/20 bg-red-400/10 p-4 text-sm text-red-100">{{ error }}</div>

    <section class="grid gap-6 xl:grid-cols-[0.85fr_1.15fr]">
      <div class="console-card">
        <div class="section-kicker">{{ $t('security.identityKicker') }}</div>
        <h3 class="section-title">{{ $t('security.identityTitle') }}</h3>
        <dl class="mt-6 space-y-4 text-sm">
          <div v-for="row in identityRows" :key="row.label" class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
            <dt class="text-xs uppercase tracking-[0.2em] text-slate-500">{{ row.label }}</dt>
            <dd class="mt-2 break-all text-slate-200">{{ row.value || '—' }}</dd>
          </div>
        </dl>
      </div>

      <div class="console-card">
        <div class="section-kicker">{{ $t('security.mfaKicker') }}</div>
        <h3 class="section-title">{{ $t('security.mfaTitle') }}</h3>
        <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t('security.mfaBody') }}</p>

        <div v-if="claims?.break_glass" class="mt-5 rounded-2xl border border-red-300/20 bg-red-400/10 p-4 text-sm text-red-100">
          {{ $t('security.breakGlassMfaBlocked') }}
        </div>

        <div v-else-if="!canManageMFA" class="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
          {{ $t('security.mfaAdminOnly') }}
        </div>

        <div v-else class="mt-5 space-y-4">
          <button type="button" class="auth-primary max-w-sm" :disabled="loadingSetup" @click="startMFASetup">
            {{ loadingSetup ? $t('common.loading') : $t('security.startMfaSetup') }}
          </button>

          <div v-if="setupUri" class="rounded-2xl border border-amber-200/20 bg-amber-200/10 p-4">
            <div class="text-sm font-semibold text-amber-100">{{ $t('security.setupUriTitle') }}</div>
            <p class="mt-2 text-sm leading-6 text-amber-100/80">{{ $t('security.setupUriBody') }}</p>
            <pre class="mt-3 overflow-x-auto rounded-xl bg-black/40 p-3 text-xs text-amber-50"><code>{{ setupUri }}</code></pre>
            <form class="mt-4 flex flex-col gap-3 sm:flex-row" @submit.prevent="confirmSetup">
              <input v-model="setupCode" inputmode="numeric" required maxlength="8" class="auth-input sm:max-w-48" :placeholder="$t('auth.mfaCode')" />
              <button type="submit" :disabled="loadingConfirm" class="rounded-xl bg-emerald-300 px-4 py-2 text-sm font-bold text-slate-950 disabled:opacity-50">
                {{ loadingConfirm ? $t('auth.verifying') : $t('security.confirmMfa') }}
              </button>
            </form>
          </div>

          <button type="button" class="rounded-xl border border-red-300/20 px-4 py-2 text-sm font-semibold text-red-200 hover:bg-red-400/10" :disabled="loadingDisable" @click="disableMFAForUser">
            {{ loadingDisable ? $t('common.loading') : $t('security.disableMfa') }}
          </button>
        </div>
      </div>
    </section>

    <section class="grid gap-6 xl:grid-cols-2">
      <div class="console-card">
        <div class="section-kicker">{{ $t('security.apiKeyKicker') }}</div>
        <h3 class="section-title">{{ $t('security.apiKeyTitle') }}</h3>
        <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t('security.apiKeyBody') }}</p>
        <div v-if="newApiKey" class="mt-5 rounded-2xl border border-amber-200/25 bg-amber-200/10 p-4">
          <div class="text-sm font-semibold text-amber-100">{{ $t('security.apiKeyOneTime') }}</div>
          <pre class="mt-3 overflow-x-auto rounded-xl bg-black/40 p-3 text-xs text-amber-50"><code>{{ newApiKey }}</code></pre>
          <button type="button" class="mt-3 text-xs font-semibold uppercase tracking-[0.18em] text-amber-100 hover:text-white" @click="newApiKey = ''">
            {{ $t('security.clearApiKey') }}
          </button>
        </div>
        <div class="mt-5 flex flex-wrap gap-3">
          <button type="button" class="auth-primary max-w-xs" :disabled="loadingKey" @click="rotateKey">{{ $t('auth.rotateKey') }}</button>
          <button type="button" class="rounded-xl border border-red-300/20 px-4 py-2 text-sm font-semibold text-red-200 hover:bg-red-400/10" :disabled="loadingRevoke" @click="revokeAllTokens">
            {{ $t('auth.revokeTokens') }}
          </button>
        </div>
      </div>

      <div class="console-card">
        <div class="section-kicker">{{ $t('security.oidcKicker') }}</div>
        <h3 class="section-title">{{ $t('security.oidcTitle') }}</h3>
        <p class="mt-2 text-sm leading-6 text-slate-400">{{ $t('security.oidcBody') }}</p>
        <a href="/api/auth/oidc/login" class="mt-5 inline-flex rounded-xl border border-cyan-200/25 bg-cyan-200/10 px-4 py-2 text-sm font-semibold text-cyan-100 hover:bg-cyan-200/15">
          {{ $t('auth.oidcLogin') }}
        </a>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { confirmMFA, disableMFA, revokeTokens, rotateAPIKey, setupMFA } from '../api/auth'
import { useAuthStore } from '../stores/auth'

const { t } = useI18n()
const auth = useAuthStore()
const claims = computed(() => auth.claims)
const canManageMFA = computed(() => claims.value?.role === 'admin')
const setupUri = ref('')
const setupToken = ref('')
const setupCode = ref('')
const newApiKey = ref('')
const message = ref('')
const error = ref('')
const loadingSetup = ref(false)
const loadingConfirm = ref(false)
const loadingDisable = ref(false)
const loadingKey = ref(false)
const loadingRevoke = ref(false)

const identityRows = computed(() => [
  { label: t('auth.email'), value: claims.value?.email },
  { label: t('auth.role'), value: claims.value?.role },
  { label: t('security.orgId'), value: claims.value?.org_id },
  { label: t('security.department'), value: claims.value?.department },
  { label: t('security.mfaVerified'), value: claims.value?.mfa_verified ? t('common.yes') : t('common.no') }
])

function setSuccess(text: string) {
  message.value = text
  error.value = ''
}

function setError(err: unknown, fallback: string) {
  const anyErr = err as { response?: { data?: { error?: string } } }
  error.value = anyErr.response?.data?.error || fallback
  message.value = ''
}

async function startMFASetup() {
  loadingSetup.value = true
  try {
    const data = await setupMFA()
    setupUri.value = data.uri
    setupToken.value = data.setup_token
    setSuccess(t('security.setupStarted'))
  } catch (err) {
    setError(err, t('security.setupFailed'))
  } finally {
    loadingSetup.value = false
  }
}

async function confirmSetup() {
  loadingConfirm.value = true
  try {
    await confirmMFA(setupToken.value, setupCode.value)
    setupUri.value = ''
    setupToken.value = ''
    setupCode.value = ''
    setSuccess(t('security.mfaEnabled'))
  } catch (err) {
    setError(err, t('security.confirmFailed'))
  } finally {
    loadingConfirm.value = false
  }
}

async function disableMFAForUser() {
  if (!window.confirm(t('security.disableConfirm'))) return
  loadingDisable.value = true
  try {
    await disableMFA()
    setSuccess(t('security.mfaDisabled'))
  } catch (err) {
    setError(err, t('security.disableFailed'))
  } finally {
    loadingDisable.value = false
  }
}

async function rotateKey() {
  loadingKey.value = true
  try {
    const data = await rotateAPIKey()
    newApiKey.value = data.api_key
    setSuccess(t('auth.rotateSuccess'))
  } catch (err) {
    setError(err, t('security.apiKeyFailed'))
  } finally {
    loadingKey.value = false
  }
}

async function revokeAllTokens() {
  if (!window.confirm(t('security.revokeConfirm'))) return
  loadingRevoke.value = true
  try {
    await revokeTokens()
    setSuccess(t('auth.revokeSuccess'))
  } catch (err) {
    setError(err, t('security.revokeFailed'))
  } finally {
    loadingRevoke.value = false
  }
}
</script>
