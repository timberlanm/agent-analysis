const STORAGE_KEY = 'soc-workbench.session-resume.v1'
const MAX_AGE_MS = 12 * 60 * 60 * 1000
const INTERNAL_ORIGIN = 'https://soc-workbench.invalid'

function browserStorage() {
  if (typeof window === 'undefined') return null
  try {
    return window.sessionStorage
  } catch (_) {
    return null
  }
}

function targetStorage(storage) {
  return storage === undefined ? browserStorage() : storage
}

export function safeInternalPath(value, fallback = '/incident') {
  if (typeof value !== 'string') return fallback
  const raw = value.trim()
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) return fallback

  try {
    const url = new URL(raw, INTERNAL_ORIGIN)
    if (url.origin !== INTERNAL_ORIGIN || url.pathname === '/login') return fallback
    return `${url.pathname}${url.search}${url.hash}`
  } catch (_) {
    return fallback
  }
}

export function saveSessionResume(payload, storage, now = Date.now()) {
  const store = targetStorage(storage)
  const username = String(payload?.username || '').trim()
  if (!store || !username) return false

  const record = {
    version: 1,
    username,
    savedAt: now,
    path: safeInternalPath(payload.path),
    viewState: payload.viewState && typeof payload.viewState === 'object'
      ? payload.viewState
      : null,
  }

  try {
    store.setItem(STORAGE_KEY, JSON.stringify(record))
    return true
  } catch (_) {
    return false
  }
}

export function peekSessionResume(username, storage, now = Date.now()) {
  const store = targetStorage(storage)
  const expectedUser = String(username || '').trim()
  if (!store || !expectedUser) return null

  try {
    const record = JSON.parse(store.getItem(STORAGE_KEY) || 'null')
    const invalid = !record
      || record.version !== 1
      || record.username !== expectedUser
      || !Number.isFinite(record.savedAt)
      || now - record.savedAt < 0
      || now - record.savedAt > MAX_AGE_MS

    if (invalid) {
      store.removeItem(STORAGE_KEY)
      return null
    }

    return {
      path: safeInternalPath(record.path),
      viewState: record.viewState && typeof record.viewState === 'object'
        ? record.viewState
        : null,
    }
  } catch (_) {
    try { store.removeItem(STORAGE_KEY) } catch (_) {}
    return null
  }
}

export function consumeSessionResume(username, storage, now = Date.now()) {
  const store = targetStorage(storage)
  const record = peekSessionResume(username, store, now)
  if (record && store) {
    try { store.removeItem(STORAGE_KEY) } catch (_) {}
  }
  return record
}

export function clearSessionResume(storage) {
  const store = targetStorage(storage)
  if (!store) return
  try { store.removeItem(STORAGE_KEY) } catch (_) {}
}

