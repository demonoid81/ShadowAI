import { strict as assert } from 'node:assert'
import {
  canManageAllOrgs,
  canManageOwnOrg,
  centsToDollars,
  dollarsToCents,
  scimTokenDisplayLifetime
} from '../src/utils/tenantUi'

assert.equal(canManageAllOrgs('global_admin'), true)
assert.equal(canManageAllOrgs('admin'), false)
assert.equal(canManageOwnOrg('admin'), true)
assert.equal(canManageOwnOrg('auditor'), false)
assert.equal(centsToDollars(12345), '123.45')
assert.equal(dollarsToCents('19.99'), 1999)
assert.equal(dollarsToCents('-10'), 0)
assert.equal(scimTokenDisplayLifetime(true), 'one_time')
assert.equal(scimTokenDisplayLifetime(false), 'not_available')

console.log('tenantUi tests ok')
