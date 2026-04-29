import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  getGovernancePolicy,
  isConfiguredPolicy,
  updateGovernancePolicy,
  type GovernancePolicy
} from '../api/governance'
import {
  emptyPolicyDraft,
  normalizeProviderRules,
  policyRiskWarnings,
  stablePolicyJSON,
  type ContextRuleDraft,
  type GovernancePolicyDraft,
  type ProviderRuleDraft,
  type RoleRuleDraft,
  type SensitivityLevel
} from '../utils/governanceUi'

function cloneDraft(policy: GovernancePolicyDraft): GovernancePolicyDraft {
  return JSON.parse(JSON.stringify(policy))
}

function asProviderRules(value: unknown): ProviderRuleDraft[] {
  if (!Array.isArray(value)) return []
  return value.map(item => {
    const rule = item as Partial<ProviderRuleDraft>
    return {
      provider: typeof rule.provider === 'string' ? rule.provider : '',
      models: Array.isArray(rule.models) ? rule.models.filter((model): model is string => typeof model === 'string') : []
    }
  })
}

function asRoleRules(value: unknown): RoleRuleDraft[] {
  if (!Array.isArray(value)) return []
  return value.map(item => {
    const rule = item as Partial<RoleRuleDraft>
    return {
      role: typeof rule.role === 'string' ? rule.role : '',
      rules: asProviderRules(rule.rules)
    }
  })
}

function asContextRules(value: unknown): ContextRuleDraft[] {
  if (!Array.isArray(value)) return []
  return value.map(item => {
    const rule = item as Partial<ContextRuleDraft>
    return {
      department: typeof rule.department === 'string' ? rule.department : '',
      role: typeof rule.role === 'string' ? rule.role : '*',
      sensitivity: Array.isArray(rule.sensitivity) ? rule.sensitivity.filter((level): level is SensitivityLevel => typeof level === 'string') : [],
      rules: asProviderRules(rule.rules)
    }
  })
}

function toDraft(policy?: Partial<GovernancePolicy>): GovernancePolicyDraft {
  const empty = emptyPolicyDraft()
  return {
    name: typeof policy?.name === 'string' ? policy.name : empty.name,
    mode: policy?.mode || empty.mode,
    rules: asProviderRules(policy?.rules),
    role_rules: asRoleRules(policy?.role_rules),
    context_rules: asContextRules(policy?.context_rules)
  }
}

function toPayload(draft: GovernancePolicyDraft): GovernancePolicy {
  return {
    name: draft.name.trim() || 'default-governance-policy',
    mode: draft.mode,
    rules: normalizeProviderRules(draft.rules),
    role_rules: draft.role_rules
      .map((rule: RoleRuleDraft) => ({ role: rule.role.trim().toLowerCase(), rules: normalizeProviderRules(rule.rules) }))
      .filter(rule => rule.role),
    context_rules: draft.context_rules.map((rule: ContextRuleDraft) => ({
      department: rule.department.trim(),
      role: (rule.role ?? '*').trim().toLowerCase(),
      sensitivity: rule.sensitivity ?? [],
      rules: normalizeProviderRules(rule.rules)
    }))
  }
}

export function useGovernancePolicy() {
  const { t } = useI18n()
  const policy = ref<GovernancePolicy | null>(null)
  const configured = ref(false)
  const loading = ref(false)
  const saving = ref(false)
  const error = ref('')
  const success = ref('')
  const jsonDraft = ref('')
  const showJson = ref(false)
  const draft = reactive<GovernancePolicyDraft>(emptyPolicyDraft())

  const warnings = computed(() => policyRiskWarnings(draft))
  const jsonPreview = computed(() => stablePolicyJSON(toPayload(draft)))

  function setDraft(next: GovernancePolicyDraft) {
    Object.assign(draft, cloneDraft(next))
    jsonDraft.value = stablePolicyJSON(toPayload(draft))
  }

  function setError(err: unknown, fallback: string) {
    const anyErr = err as { response?: { data?: { error?: string }, status?: number }, message?: string }
    error.value = anyErr.response?.data?.error || anyErr.message || fallback
    success.value = ''
  }

  async function loadPolicy() {
    loading.value = true
    error.value = ''
    try {
      const data = await getGovernancePolicy()
      if (isConfiguredPolicy(data)) {
        policy.value = data
        configured.value = true
        setDraft(toDraft(data))
      } else {
        policy.value = null
        configured.value = false
        setDraft(emptyPolicyDraft())
      }
    } catch (err) {
      setError(err, t('policies.governance.errors.loadFailed'))
    } finally {
      loading.value = false
    }
  }

  function applyJSONDraft() {
    try {
      const parsed = JSON.parse(jsonDraft.value)
      setDraft(toDraft(parsed))
      success.value = t('policies.governance.messages.jsonApplied')
      error.value = ''
    } catch {
      error.value = t('policies.governance.errors.invalidJson')
      success.value = ''
    }
  }

  async function savePolicy() {
    saving.value = true
    error.value = ''
    try {
      const saved = await updateGovernancePolicy(toPayload(draft))
      policy.value = saved
      configured.value = true
      setDraft(toDraft(saved))
      success.value = t('policies.governance.messages.saved')
    } catch (err) {
      setError(err, t('policies.governance.errors.saveFailed'))
    } finally {
      saving.value = false
    }
  }

  return {
    policy, configured, loading, saving, error, success, draft, warnings, jsonPreview, jsonDraft, showJson,
    loadPolicy, savePolicy, applyJSONDraft
  }
}
