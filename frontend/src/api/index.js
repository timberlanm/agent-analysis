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

// 读取 cookie（用于取 CSRF 双提交令牌）
export function getCookie(name) {
  if (typeof document === 'undefined') return ''
  const escaped = name.replace(/([.$?*|{}()\[\]\\/+^])/g, '\\$1')
  const m = document.cookie.match('(?:^|; )' + escaped + '=([^;]*)')
  return m ? decodeURIComponent(m[1]) : ''
}

// 携带会话 cookie 的写请求需回传 CSRF 头
export function csrfHeaders() {
  return { 'X-CSRF-Token': getCookie('csrf_token') }
}

// 会话过期/未登录时通知全局（App 监听后跳登录页）
function notifyUnauthorized() {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('auth-unauthorized'))
  }
}

async function request(url, options = {}) {
  const controller = new AbortController()
  const timeoutMs = options.timeout || 30000
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  const fetchOpts = {
    ...options,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    signal: options.signal || controller.signal,
  }
  const method = (fetchOpts.method || 'GET').toUpperCase()
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    Object.assign(fetchOpts.headers, csrfHeaders())
  }
  if (options.signal) clearTimeout(timer)

  try {
    const resp = await fetch(apiUrl(url), fetchOpts)
    // /auth/* 自行处理 401（登录前的探测），其余接口 401 视为会话失效
    if (resp.status === 401 && !url.startsWith('/auth/')) notifyUnauthorized()
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
export function assignIncidentHandler(id, name) {
  return request(`/incident/alerts/${id}/handlers`, { method: 'POST', body: JSON.stringify({ name }) })
}
export function removeIncidentHandler(id, name) {
  return request(`/incident/alerts/${id}/handlers`, { method: 'DELETE', body: JSON.stringify({ name }) })
}
export function setIncidentHandlers(id, names) {
  return request(`/incident/alerts/${id}/handlers`, { method: 'PUT', body: JSON.stringify({ names }) })
}
export function rejectIncidentAlert(id, reason = '') {
  return request(`/incident/alerts/${id}/reject`, { method: 'POST', body: JSON.stringify({ reason }) })
}
export function reopenIncidentAlert(id, conclusion, reason = '') {
  return request(`/incident/alerts/${id}/reopen`, { method: 'POST', body: JSON.stringify({ conclusion, reason }) })
}
export function listIncidentSubtasks(id) { return request(`/incident/alerts/${id}/subtasks`) }
export function addIncidentSubtask(id, data) {
  return request(`/incident/alerts/${id}/subtasks`, { method: 'POST', body: JSON.stringify(data) })
}
export function updateIncidentSubtask(subtaskId, data) {
  return request(`/incident/subtasks/${subtaskId}`, { method: 'PUT', body: JSON.stringify(data) })
}
export function deleteIncidentSubtask(subtaskId) {
  return request(`/incident/subtasks/${subtaskId}`, { method: 'DELETE' })
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
export function getIncidentAudit(params = {}) {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') q.append(k, v)
  }
  const qs = q.toString()
  return request(`/incident/audit${qs ? '?' + qs : ''}`)
}
export function verifyIncidentAudit() { return request('/incident/audit/verify') }
export async function exportIncidentAuditCsv(params = {}) {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') q.append(k, v)
  }
  const qs = q.toString()
  const resp = await fetch(apiUrl(`/incident/audit/export${qs ? '?' + qs : ''}`), { credentials: 'include' })
  if (resp.status === 401) notifyUnauthorized()
  const text = await resp.text()
  if (!resp.ok) throw new Error(text || '导出失败')
  return text
}
export function exportIncidentAlert(id) { return request(`/incident/alerts/${id}/export`) }
export async function exportIncidentAlertMarkdown(id) {
  const resp = await fetch(apiUrl(`/incident/alerts/${id}/export?format=markdown`), { credentials: 'include' })
  if (resp.status === 401) notifyUnauthorized()
  const text = await resp.text()
  if (!resp.ok) throw new Error(text || '导出失败')
  return text
}
export async function exportIncidentOperationsCsv(days = 7) {
  const resp = await fetch(apiUrl(`/incident/operations/export?days=${days}`), { credentials: 'include' })
  if (resp.status === 401) notifyUnauthorized()
  const text = await resp.text()
  if (!resp.ok) throw new Error(text || '导出失败')
  return text
}

export async function uploadIncidentAttachments(alertId, files, description = '') {
  const form = new FormData()
  for (const file of files) form.append('file', file)
  if (description) form.append('description', description)
  const resp = await fetch(apiUrl(`/incident/alerts/${alertId}/attachments`), {
    method: 'POST', body: form, credentials: 'include', headers: csrfHeaders(),
  })
  if (resp.status === 401) notifyUnauthorized()
  const data = await resp.json()
  if (!resp.ok) throw new Error(data.error || '上传失败')
  return data
}
export async function uploadIncidentAttachment(alertId, file, description = '') {
  return uploadIncidentAttachments(alertId, [file], description)
}
export async function downloadIncidentAttachment(attachment) {
  if (!attachment?.url) throw new Error('附件下载地址不存在')
  if (attachment.file_available === false) throw new Error('附件源文件缺失，请联系管理员恢复')

  const url = attachment.url.startsWith('/api/')
    ? `${API_BASE}${attachment.url}`
    : attachment.url
  const resp = await fetch(url, { credentials: 'include' })
  if (resp.status === 401) notifyUnauthorized()
  if (!resp.ok) {
    let message = `下载失败 (HTTP ${resp.status})`
    const bodyText = await resp.text()
    try {
      const body = JSON.parse(bodyText)
      message = body.error || message
    } catch (_) {
      if (bodyText) message = bodyText
    }
    throw new Error(message)
  }

  const blob = await resp.blob()
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = objectUrl
  link.download = attachment.original_name || attachment.filename || 'attachment'
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000)
}
export function deleteIncidentAttachment(id) { return request(`/incident/attachments/${id}`, { method: 'DELETE' }) }

// Legacy helpers kept for compatibility with older screens/scripts.
export async function uploadIncidentImage(file) {
  const form = new FormData()
  form.append('image', file)
  const resp = await fetch(apiUrl('/incident/upload_image'), {
    method: 'POST', body: form, credentials: 'include', headers: csrfHeaders(),
  })
  if (resp.status === 401) notifyUnauthorized()
  const data = await resp.json()
  if (!resp.ok) throw new Error(data.error || '上传失败')
  return data
}
export async function uploadIncidentAlertFile(file) {
  const form = new FormData()
  form.append('alert', file)
  const resp = await fetch(apiUrl('/incident/upload_alert'), {
    method: 'POST', body: form, credentials: 'include', headers: csrfHeaders(),
  })
  if (resp.status === 401) notifyUnauthorized()
  const data = await resp.json()
  if (!resp.ok) throw new Error(data.error || '上传失败')
  return data
}
export function uploadIncidentAlertJson(json) { return createIncidentAlert(json) }
export function listIncidentImages() { return request('/incident/images') }
export function deleteIncidentImage(id) { return request(`/incident/images/${id}`, { method: 'DELETE' }) }
export function exportIncident() { return request('/incident/export') }
export function clearIncident() { return request('/incident/clear', { method: 'POST' }) }

// ==================== 认证 / 账号（Auth / RBAC） ====================
export function authLogin(username, password) {
  return request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) })
}
export function authLogout() { return request('/auth/logout', { method: 'POST' }) }
export function authMe() { return request('/auth/me') }
// 指派选人目录（供有 alert.assign / subtask.manage 权限者读取）
export function getAuthDirectory(role = '') {
  return request(`/auth/directory${role ? '?role=' + encodeURIComponent(role) : ''}`)
}
export function authChangePassword(oldPassword, newPassword) {
  return request('/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
  })
}
// 用户管理（仅 system.manage）
export function listAuthUsers() { return request('/auth/users') }
export function createAuthUser(data) {
  return request('/auth/users', { method: 'POST', body: JSON.stringify(data) })
}
export function updateAuthUser(id, data) {
  return request(`/auth/users/${id}`, { method: 'PUT', body: JSON.stringify(data) })
}
export function resetAuthUserPassword(id, password) {
  return request(`/auth/users/${id}/password`, { method: 'POST', body: JSON.stringify({ password }) })
}
// 服务令牌（自动化入库，仅管理员）
export function listApiTokens() { return request('/auth/tokens') }
export function createApiToken(data) {
  return request('/auth/tokens', { method: 'POST', body: JSON.stringify(data) })
}
export function revokeApiToken(id) { return request(`/auth/tokens/${id}`, { method: 'DELETE' }) }
// 角色-权限矩阵（可配置，仅管理员）
export function getRolePermissions() { return request('/auth/permissions') }
export function setRolePermissions(roleCode, permissions) {
  return request(`/auth/roles/${roleCode}/permissions`, { method: 'PUT', body: JSON.stringify({ permissions }) })
}
