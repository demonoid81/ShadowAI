export type GovernanceMode = 'disabled' | 'allowlist_strict' | 'role_based' | 'context_scoped'
export type SensitivityLevel = 'standard' | 'confidential' | 'restricted' | 'unknown'

export interface ProviderRuleDraft {
  provider: string
  models: string[]
}

export interface RoleRuleDraft {
  role: string
  rules: ProviderRuleDraft[]
}

export interface ContextRuleDraft {
  department: string
  role?: string
  sensitivity?: SensitivityLevel[]
  rules: ProviderRuleDraft[]
}

export interface GovernancePolicyDraft {
  name: string
  mode: GovernanceMode
  rules: ProviderRuleDraft[]
  role_rules: RoleRuleDraft[]
  context_rules: ContextRuleDraft[]
}

export const governanceModes: GovernanceMode[] = ['disabled', 'allowlist_strict', 'role_based', 'context_scoped']
export const sensitivityLevels: SensitivityLevel[] = ['standard', 'confidential', 'restricted', 'unknown']

export function splitModels(input: string): string[] {
  return input
    .split(',')
    .map(item => item.trim().toLowerCase())
    .filter(Boolean)
    .filter((item, index, arr) => arr.indexOf(item) === index)
}

export function joinModels(models: string[]): string {
  return models.join(', ')
}

export function normalizeProviderRules(rules: ProviderRuleDraft[]): ProviderRuleDraft[] {
  const merged = new Map<string, Set<string>>()
  for (const rule of rules) {
    const provider = rule.provider.trim().toLowerCase()
    if (!provider) continue
    if (!merged.has(provider)) merged.set(provider, new Set())
    for (const model of rule.models) {
      const normalized = model.trim().toLowerCase()
      if (normalized) merged.get(provider)?.add(normalized)
    }
  }
  return [...merged.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([provider, modelSet]) => ({ provider, models: [...modelSet].sort() }))
}

export function emptyProviderRule(): ProviderRuleDraft {
  return { provider: '', models: [] }
}

export function emptyRoleRule(): RoleRuleDraft {
  return { role: '', rules: [emptyProviderRule()] }
}

export function emptyContextRule(): ContextRuleDraft {
  return { department: '', role: '*', sensitivity: ['standard'], rules: [emptyProviderRule()] }
}

export function emptyPolicyDraft(): GovernancePolicyDraft {
  return {
    name: 'default-governance-policy',
    mode: 'disabled',
    rules: [],
    role_rules: [],
    context_rules: []
  }
}

export function hasUsableProviderRule(rules: ProviderRuleDraft[]): boolean {
  return normalizeProviderRules(rules).some(rule => rule.provider && rule.models.length > 0)
}

export function policyRiskWarnings(policy: GovernancePolicyDraft): string[] {
  const warnings: string[] = []
  if (policy.mode === 'allowlist_strict' && !hasUsableProviderRule(policy.rules)) {
    warnings.push('strict_without_rules')
  }
  if (policy.mode === 'role_based' && policy.role_rules.length === 0) {
    warnings.push('role_based_without_roles')
  }
  if (policy.mode === 'context_scoped') {
    if (policy.context_rules.length === 0) warnings.push('context_scoped_without_context')
    if (policy.context_rules.some(rule => !hasUsableProviderRule(rule.rules))) {
      warnings.push('context_rule_without_provider_rules')
    }
  }
  return warnings
}

export function stablePolicyJSON(policy: GovernancePolicyDraft): string {
  return JSON.stringify(policy, null, 2)
}
