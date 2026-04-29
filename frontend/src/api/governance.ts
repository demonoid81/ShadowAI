import api from './client'
import type { ContextRuleDraft, GovernanceMode, ProviderRuleDraft, RoleRuleDraft } from '../utils/governanceUi'

export interface GovernancePolicy {
  id?: string
  name: string
  mode: GovernanceMode
  rules: ProviderRuleDraft[]
  role_rules: RoleRuleDraft[]
  context_rules: ContextRuleDraft[]
  updated_at?: string
  updated_by?: string
  is_active?: boolean
}

export interface EmptyGovernancePolicyResponse {
  configured: false
}

export type GovernancePolicyResponse = GovernancePolicy | EmptyGovernancePolicyResponse

export function isConfiguredPolicy(data: GovernancePolicyResponse): data is GovernancePolicy {
  return !('configured' in data && data.configured === false)
}

export async function getGovernancePolicy(): Promise<GovernancePolicyResponse> {
  const { data } = await api.get<GovernancePolicyResponse>('/governance/policy')
  return data
}

export async function updateGovernancePolicy(policy: GovernancePolicy): Promise<GovernancePolicy> {
  const { data } = await api.put<GovernancePolicy>('/governance/policy', {
    name: policy.name,
    mode: policy.mode,
    rules: policy.rules ?? [],
    role_rules: policy.role_rules ?? [],
    context_rules: policy.context_rules ?? []
  })
  return data
}
