import { strict as assert } from 'node:assert'
import {
  emptyContextRule,
  emptyPolicyDraft,
  joinModels,
  normalizeProviderRules,
  policyRiskWarnings,
  splitModels,
  stablePolicyJSON
} from '../src/utils/governanceUi'

assert.deepEqual(splitModels('GPT-4, gpt-4, claude-3 ,'), ['gpt-4', 'claude-3'])
assert.equal(joinModels(['gpt-4', 'claude-3']), 'gpt-4, claude-3')
assert.deepEqual(
  normalizeProviderRules([
    { provider: 'OpenAI ', models: [' GPT-4', 'gpt-4o'] },
    { provider: 'openai', models: ['gpt-4'] },
    { provider: 'Anthropic', models: ['claude-3'] }
  ]),
  [
    { provider: 'anthropic', models: ['claude-3'] },
    { provider: 'openai', models: ['gpt-4', 'gpt-4o'] }
  ]
)

assert.deepEqual(policyRiskWarnings({ ...emptyPolicyDraft(), mode: 'allowlist_strict' }), ['strict_without_rules'])
assert.deepEqual(policyRiskWarnings({ ...emptyPolicyDraft(), mode: 'role_based' }), ['role_based_without_roles'])
assert.deepEqual(policyRiskWarnings({ ...emptyPolicyDraft(), mode: 'context_scoped' }), ['context_scoped_without_context'])
assert.deepEqual(
  policyRiskWarnings({ ...emptyPolicyDraft(), mode: 'context_scoped', context_rules: [emptyContextRule()] }),
  ['context_rule_without_provider_rules']
)
assert.equal(stablePolicyJSON({ ...emptyPolicyDraft(), name: 'x' }).includes('"name": "x"'), true)

console.log('governanceUi tests ok')
