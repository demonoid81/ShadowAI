import { strict as assert } from 'node:assert'
import {
  countByStatus,
  legalHoldActions,
  requiresSafetyConfirm,
  safeMetadataPreview,
  selectedPendingIDs
} from '../src/utils/legalHoldUi'

assert.deepEqual(legalHoldActions('pending'), ['approve', 'reject'])
assert.deepEqual(legalHoldActions('active'), ['release'])
assert.deepEqual(legalHoldActions('release_pending'), ['approve-release', 'reject-release'])
assert.deepEqual(legalHoldActions('released'), [])
assert.equal(requiresSafetyConfirm('release'), true)
assert.equal(requiresSafetyConfirm('approve'), false)
assert.deepEqual(countByStatus([{ status: 'pending' }, { status: 'pending' }, { status: 'active' }]), { pending: 2, active: 1 })
assert.deepEqual(
  selectedPendingIDs([{ id: 'a', status: 'pending' }, { id: 'b', status: 'active' }], new Set(['a', 'b'])),
  ['a']
)
assert.equal(safeMetadataPreview('{"a":1}'), '{\n  "a": 1\n}')
assert.equal(safeMetadataPreview('not-json'), 'not-json')

console.log('legalHoldUi tests ok')
