import test from 'node:test'
import assert from 'node:assert/strict'
import {
  clearSessionResume,
  consumeSessionResume,
  peekSessionResume,
  safeInternalPath,
  saveSessionResume,
} from '../src/utils/sessionResume.js'

function memoryStorage() {
  const values = new Map()
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  }
}

test('safeInternalPath only accepts protected in-app paths', () => {
  assert.equal(safeInternalPath('/incident?queue=my#detail'), '/incident?queue=my#detail')
  assert.equal(safeInternalPath('https://attacker.example/'), '/incident')
  assert.equal(safeInternalPath('//attacker.example/'), '/incident')
  assert.equal(safeInternalPath('/login?redirect=/incident'), '/incident')
  assert.equal(safeInternalPath('/\\attacker.example'), '/incident')
})

test('resume state is restored once for the same account', () => {
  const storage = memoryStorage()
  const now = 10_000
  const viewState = { kind: 'incident', selectedAlertId: 'alert-1' }

  assert.equal(saveSessionResume({
    username: 'analyst',
    path: '/incident?queue=my',
    viewState,
  }, storage, now), true)

  assert.deepEqual(peekSessionResume('analyst', storage, now + 100), {
    path: '/incident?queue=my',
    viewState,
  })
  assert.deepEqual(consumeSessionResume('analyst', storage, now + 100), {
    path: '/incident?queue=my',
    viewState,
  })
  assert.equal(peekSessionResume('analyst', storage, now + 100), null)
})

test('resume state is rejected for a different account or after expiry', () => {
  const accountStorage = memoryStorage()
  saveSessionResume({ username: 'analyst', path: '/incident' }, accountStorage, 1_000)
  assert.equal(peekSessionResume('other-user', accountStorage, 1_100), null)

  const expiredStorage = memoryStorage()
  saveSessionResume({ username: 'analyst', path: '/incident' }, expiredStorage, 1_000)
  assert.equal(peekSessionResume('analyst', expiredStorage, 13 * 60 * 60 * 1000), null)

  clearSessionResume(expiredStorage)
})

