import { strict as assert } from 'node:assert'
import { formatProductionDetails, formatSeconds } from '../src/utils/operationsStatus'

assert.equal(formatSeconds(0), '0s')
assert.equal(formatSeconds(59), '59s')
assert.equal(formatSeconds(7200), '2h')
assert.equal(formatSeconds(93600), '1d 2h')

const details = formatProductionDetails({
  stale_after_seconds: 93600,
  last_success_at: '2026-04-29T03:00:00Z',
  age_seconds: 7200,
  query_configured: true,
  value: 0
})

assert.deepEqual(
  details.map((item) => item.key),
  ['query_configured', 'value', 'last_success_configured', 'last_success_at', 'age_seconds', 'stale_after_seconds'].filter((key) => key !== 'last_success_configured')
)
assert.equal(details.find((item) => item.key === 'last_success_at')?.value, '2026-04-29T03:00:00.000Z')
assert.equal(details.find((item) => item.key === 'age_seconds')?.value, '2h')
assert.equal(details.find((item) => item.key === 'stale_after_seconds')?.value, '1d 2h')

const fallback = formatProductionDetails({ custom: { nested: true } })
assert.equal(fallback[0].labelKey, 'operations.detailLabels.other')
assert.equal(fallback[0].value, '{"nested":true}')

console.log('operationsStatus tests ok')
