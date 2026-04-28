import { strict as assert } from 'node:assert'
import { isOIDCEntrypointSafe, nextAuthDestination, shouldShowBreakGlassWarning } from '../src/utils/authFlow'

assert.equal(nextAuthDestination(null, true), 'mfa_verify')
assert.equal(nextAuthDestination({ role: 'admin' }, false), 'security_enrollment')
assert.equal(nextAuthDestination({ role: 'global_admin', mfa_verified: true }, false), 'dashboard')
assert.equal(nextAuthDestination({ role: 'admin', break_glass: true }, false), 'dashboard')
assert.equal(nextAuthDestination({ role: 'user' }, false), 'dashboard')
assert.equal(shouldShowBreakGlassWarning('   '), false)
assert.equal(shouldShowBreakGlassWarning('emergency-secret'), true)
assert.equal(isOIDCEntrypointSafe('/api/auth/oidc/login'), true)
assert.equal(isOIDCEntrypointSafe('https://idp.example/login'), false)

console.log('authFlow tests ok')
