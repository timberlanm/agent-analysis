const DB_NAME = 'soc-workbench-session'
const DB_VERSION = 1
const STORE_NAME = 'drafts'
const MAX_AGE_MS = 12 * 60 * 60 * 1000

function openDatabase() {
  if (typeof indexedDB === 'undefined') return Promise.resolve(null)
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'username' })
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error || new Error('无法打开本地草稿存储'))
  })
}

function runTransaction(mode, operation) {
  return openDatabase().then((db) => {
    if (!db) return null
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, mode)
      const store = transaction.objectStore(STORE_NAME)
      let request
      try {
        request = operation(store)
      } catch (error) {
        db.close()
        reject(error)
        return
      }
      request.onsuccess = () => resolve(request.result ?? null)
      request.onerror = () => reject(request.error || new Error('本地草稿操作失败'))
      transaction.oncomplete = () => db.close()
      transaction.onabort = () => db.close()
    })
  })
}

export async function saveSessionDraft(username, data, now = Date.now()) {
  const owner = String(username || '').trim()
  if (!owner) return false
  try {
    await runTransaction('readwrite', (store) => store.put({
      username: owner,
      version: 1,
      savedAt: now,
      data,
    }))
    return true
  } catch (_) {
    return false
  }
}

export async function peekSessionDraft(username, now = Date.now()) {
  const owner = String(username || '').trim()
  if (!owner) return null
  try {
    const record = await runTransaction('readonly', (store) => store.get(owner))
    const invalid = !record
      || record.version !== 1
      || record.username !== owner
      || !Number.isFinite(record.savedAt)
      || now - record.savedAt < 0
      || now - record.savedAt > MAX_AGE_MS
    if (invalid) {
      if (record) await clearSessionDraft(owner)
      return null
    }
    return record.data && typeof record.data === 'object' ? record.data : null
  } catch (_) {
    return null
  }
}

export async function clearSessionDraft(username) {
  const owner = String(username || '').trim()
  if (!owner) return
  try {
    await runTransaction('readwrite', (store) => store.delete(owner))
  } catch (_) {}
}
