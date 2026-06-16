/**
 * API Client — Incident Analysis
 * ================================
 * 特点：
 * 1. 自动检测后端地址（开发模式直连 localhost:5000，生产模式使用页面同源）
 * 2. 统一的错误处理 + 超时机制
 * 3. 零外部依赖（仅 fetch）
 */

// ---------- 后端地址自动检测 ----------
const __api_base = (() => {
  if (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE) {
    return import.meta.env.VITE_API_BASE
  }

  if (typeof window !== 'undefined' && window.location) {
    const loc = window.location

    // Flask 直接托管前端（同源）
    if (loc.port === '5000' || loc.port === '') {
      return ''
    }

    // Vite dev server (port 3000) → 直连 Flask (port 5000)
    if (loc.port === '3000') {
      return 'http://localhost:5000'
    }
  }

  return 'http://localhost:5000'
})()

const API_BASE = __api_base
console.log(`[API] 后端基址: "${API_BASE || '(同源)'}"`)

// ---------- 通用请求（JSON API） ----------
function apiUrl(path) {
  if (!API_BASE) return `/api${path}`
  return `${API_BASE}/api${path}`
}

async function request(url, options = {}) {
  const controller = new AbortController()
  const timeoutMs = options.timeout || 30000
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  const fetchOpts = {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    signal: options.signal || controller.signal,
    ...options,
  }
  if (options.signal) {
    fetchOpts.signal = options.signal
    clearTimeout(timer)
  }

  try {
    const resp = await fetch(apiUrl(url), fetchOpts)
    if (!resp.ok) {
      let errMsg = `HTTP ${resp.status}`
      try { const body = await resp.json(); errMsg = body.error || errMsg } catch (_) {}
      throw new Error(errMsg)
    }
    return await resp.json()
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(`请求超时 (${timeoutMs / 1000}s)`)
    throw e
  } finally {
    clearTimeout(timer)
  }
}

// ==================== Incident（研判分析） ====================
export function listIncidentAlerts(params = {}) {
  const q = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') q.append(key, value)
  }
  const qs = q.toString()
  return request(`/incident/alerts${qs ? '?' + qs : ''}`)
}
export function createIncidentAlert(data) {
  return request('/incident/alerts', { method: 'POST', body: JSON.stringify(data) })
}
export function getIncidentAlert(id) { return request(`/incident/alerts/${id}`) }
export function updateIncidentAlert(id, data) {
  return request(`/incident/alerts/${id}`, { method: 'PUT', body: JSON.stringify(data) })
}
export function deleteIncidentAlert(id) { return request(`/incident/alerts/${id}`, { method: 'DELETE' }) }
export function batchIncidentAlerts(ids, action, payload = {}) {
  return request('/incident/alerts/batch', {
    method: 'POST',
    body: JSON.stringify({ ids, action, payload })
  })
}
export function setIncidentAlertStatus(id, status, payload = '') {
  const body = typeof payload === 'object' && payload !== null
    ? { status, ...payload }
    : { status, reason: payload }
  return request(`/incident/alerts/${id}/status`, { method: 'POST', body: JSON.stringify(body) })
}
export function setIncidentAlertConclusion(id, conclusion, content = '') {
  return request(`/incident/alerts/${id}/conclusion`, { method: 'POST', body: JSON.stringify({ conclusion, content }) })
}
export function escalateIncidentAlert(id, payload) {
  return request(`/incident/alerts/${id}/escalate`, { method: 'POST', body: JSON.stringify(payload) })
}
export function addIncidentNote(id, content, noteType = 'manual') {
  return request(`/incident/alerts/${id}/notes`, { method: 'POST', body: JSON.stringify({ content, note_type: noteType }) })
}
export function addIncidentEntity(id, entity) {
  return request(`/incident/alerts/${id}/entities`, { method: 'POST', body: JSON.stringify(entity) })
}
export function deleteIncidentEntity(entityId) { return request(`/incident/entities/${entityId}`, { method: 'DELETE' }) }
export function getIncidentRelated(id) { return request(`/incident/alerts/${id}/related`) }
export function getIncidentCorrelation(id, limit = 20) { return request(`/incident/alerts/${id}/correlation?limit=${limit}`) }
export function getIncidentStats() { return request('/incident/stats') }
export function getIncidentOperations(days = 7) { return request(`/incident/operations/summary?days=${days}`) }
export function getIncidentTemplates() { return request('/incident/templates') }
export function getIncidentAudit(limit = 100) { return request(`/incident/audit?limit=${limit}`) }
export function exportIncidentAlert(id) { return request(`/incident/alerts/${id}/export`) }
export async function exportIncidentAlertMarkdown(id) {
  const resp = await fetch(apiUrl(`/incident/alerts/${id}/export?format=markdown`))
  const text = await resp.text()
  if (!resp.ok) throw new Error(text || '导出失败')
  return text
}
export async function exportIncidentOperationsCsv(days = 7) {
  const resp = await fetch(apiUrl(`/incident/operations/export?days=${days}`))
  const text = await resp.text()
  if (!resp.ok) throw new Error(text || '导出失败')
  return text
}

export async function uploadIncidentAttachment(alertId, file, description = '') {
  const form = new FormData()
  form.append('file', file)
  if (description) form.append('description', description)
  const resp = await fetch(apiUrl(`/incident/alerts/${alertId}/attachments`), { method: 'POST', body: form })
  const data = await resp.json()
  if (!resp.ok) throw new Error(data.error || '上传失败')
  return data
}
export function deleteIncidentAttachment(id) { return request(`/incident/attachments/${id}`, { method: 'DELETE' }) }

// Legacy helpers kept for compatibility with older screens/scripts.
export async function uploadIncidentImage(file) {
  const form = new FormData()
  form.append('image', file)
  const resp = await fetch(apiUrl('/incident/upload_image'), { method: 'POST', body: form })
  const data = await resp.json()
  if (!resp.ok) throw new Error(data.error || '上传失败')
  return data
}
export async function uploadIncidentAlertFile(file) {
  const form = new FormData()
  form.append('alert', file)
  const resp = await fetch(apiUrl('/incident/upload_alert'), { method: 'POST', body: form })
  const data = await resp.json()
  if (!resp.ok) throw new Error(data.error || '上传失败')
  return data
}
export function uploadIncidentAlertJson(json) { return createIncidentAlert(json) }
export function listIncidentImages() { return request('/incident/images') }
export function deleteIncidentImage(id) { return request(`/incident/images/${id}`, { method: 'DELETE' }) }
export function exportIncident() { return request('/incident/export') }
export function clearIncident() { return request('/incident/clear', { method: 'POST' }) }
