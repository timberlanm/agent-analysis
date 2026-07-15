/**
 * 认证状态 Store（轻量 reactive，项目未引入 Pinia）
 * 持有当前登录用户 + 角色 + 权限,提供 hasPerm/hasRole 供路由守卫与界面按权限显隐。
 */
import { reactive } from 'vue'
import { authLogin, authLogout, authMe } from '../api'

export const auth = reactive({
  user: null,
  roles: [],        // 角色 code 列表
  permissions: [],  // 权限 code 列表
  loaded: false,    // 是否已完成首次 /me 探测

  get username() {
    return this.user?.username || ''
  },
  get displayName() {
    return this.user?.display_name || this.user?.username || ''
  },
  get isAuthenticated() {
    return !!this.user
  },
  get mustChangePassword() {
    return !!this.user?.must_change_password
  },

  hasPerm(perm) {
    return this.permissions.includes(perm)
  },
  hasRole(code) {
    return this.roles.includes(code)
  },

  _set(data) {
    this.user = data || null
    this.permissions = (data && data.permissions) || []
    this.roles = ((data && data.roles) || []).map((r) => (typeof r === 'string' ? r : r.code))
  },
  _clear() {
    this.user = null
    this.roles = []
    this.permissions = []
  },

  /** 首次进入应用时探测会话状态（幂等） */
  async load(force = false) {
    if (this.loaded && !force) return this.user
    try {
      const res = await authMe()
      this._set(res.data)
    } catch (e) {
      this._clear()
    } finally {
      this.loaded = true
    }
    return this.user
  },

  async login(username, password) {
    const res = await authLogin(username, password)
    this._set(res.data)
    this.loaded = true
    return res.data
  },

  async logout() {
    try {
      await authLogout()
    } catch (e) {
      /* 忽略网络错误,前端状态仍需清空 */
    }
    this._clear()
  },
})
