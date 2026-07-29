import test from 'node:test'
import assert from 'node:assert/strict'
import { shouldIgnoreRowClick } from '../src/utils/tableInteraction.js'

test('row click is ignored while the user has selected text', () => {
  const event = { target: { closest: () => null } }
  assert.equal(shouldIgnoreRowClick(event, 'SOC-20260729-000001'), true)
})

test('row click is ignored for interactive controls', () => {
  const event = { target: { closest: () => ({ tagName: 'BUTTON' }) } }
  assert.equal(shouldIgnoreRowClick(event, ''), true)
})

test('plain row click still opens the alert', () => {
  const event = { target: { closest: () => null } }
  assert.equal(shouldIgnoreRowClick(event, ''), false)
})

