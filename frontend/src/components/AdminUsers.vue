<template>
  <el-drawer :model-value="modelValue" title="账号与令牌管理" size="720px" :append-to-body="true"
             @update:model-value="(v) => emit('update:modelValue', v)" @open="onOpen">
    <el-tabs v-model="activeTab">
      <!-- ============ 账号 ============ -->
      <el-tab-pane label="账号" name="users">
        <div class="au-toolbar">
          <el-button type="primary" size="small" @click="openCreate">
            <el-icon><Plus /></el-icon>新建账号
          </el-button>
          <el-button size="small" :loading="loading" @click="loadUsers">刷新</el-button>
        </div>

        <el-table :data="users" size="small" v-loading="loading" style="width: 100%">
          <el-table-column label="用户名" prop="username" min-width="110" />
          <el-table-column label="姓名" prop="display_name" min-width="100" />
          <el-table-column label="角色" min-width="150">
            <template #default="{ row }">
              <el-tag v-for="r in row.roles" :key="r.code" size="small" class="au-role-tag">{{ r.name }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="80">
            <template #default="{ row }">
              <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="200">
            <template #default="{ row }">
              <el-button link type="primary" size="small" @click="openRoles(row)">角色</el-button>
              <el-button link type="primary" size="small" @click="resetPassword(row)">重置口令</el-button>
              <el-button link :type="row.status === 'active' ? 'danger' : 'success'" size="small"
                         @click="toggleStatus(row)">
                {{ row.status === 'active' ? '停用' : '启用' }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ============ 接口令牌 ============ -->
      <el-tab-pane label="接口令牌" name="tokens">
        <div class="au-toolbar">
          <el-button type="primary" size="small" @click="openCreateToken">
            <el-icon><Plus /></el-icon>新建令牌
          </el-button>
          <el-button size="small" :loading="tokenLoading" @click="loadTokens">刷新</el-button>
          <span class="au-hint">供 SIEM / EDR 等系统自动化推送告警，仅限低危入库权限</span>
        </div>

        <el-table :data="tokens" size="small" v-loading="tokenLoading" style="width: 100%">
          <el-table-column label="名称" prop="name" min-width="120" />
          <el-table-column label="前缀" width="120">
            <template #default="{ row }"><code>{{ row.token_prefix }}…</code></template>
          </el-table-column>
          <el-table-column label="权限" min-width="160">
            <template #default="{ row }">
              <el-tag v-for="s in row.scopes" :key="s" size="small" class="au-role-tag">{{ s }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="80">
            <template #default="{ row }">
              <el-tag :type="tokenStatusType(row)" size="small">{{ tokenStatusLabel(row) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="最近使用" min-width="120">
            <template #default="{ row }">{{ row.last_used_at ? fmt(row.last_used_at) : '从未' }}</template>
          </el-table-column>
          <el-table-column label="操作" width="80">
            <template #default="{ row }">
              <el-button v-if="!row.revoked" link type="danger" size="small" @click="revokeToken(row)">吊销</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ============ 角色权限 ============ -->
      <el-tab-pane label="角色权限" name="perms">
        <div class="au-toolbar">
          <span class="au-hint">保存后立即生效；对象类权限仍受本人经手/受指派范围限制，高风险权限仅管理员持有。</span>
          <el-button size="small" type="primary" :loading="permSaving" @click="savePerms">保存</el-button>
          <el-button size="small" :loading="permLoading" @click="loadPerms">刷新</el-button>
        </div>
        <div class="au-matrix-wrap" v-loading="permLoading">
          <table class="au-matrix" v-if="catalog.length">
            <thead>
              <tr>
                <th class="au-perm-col">权限＼角色</th>
                <th v-for="r in roles" :key="r.code">{{ r.name }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="p in catalog" :key="p.code">
                <td class="au-perm-col">
                  <span class="au-cat">{{ p.category }}</span>{{ p.name }}
                  <small v-if="adminOnlyPermissions.has(p.code)" class="au-risk">仅管理员</small>
                </td>
                <td v-for="r in roles" :key="r.code" class="au-check-cell">
                  <el-checkbox v-if="editMatrix[r.code]" v-model="editMatrix[r.code][p.code]"
                               :disabled="r.code === 'admin' || adminOnlyPermissions.has(p.code)" />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- 新建账号 -->
    <el-dialog v-model="createVisible" title="新建账号" width="440px" append-to-body>
      <el-form label-width="72px">
        <el-form-item label="用户名"><el-input v-model="createForm.username" placeholder="登录名" /></el-form-item>
        <el-form-item label="姓名"><el-input v-model="createForm.display_name" placeholder="显示名（可选）" /></el-form-item>
        <el-form-item label="初始口令">
          <el-input v-model="createForm.password" placeholder="至少 12 位" show-password />
        </el-form-item>
        <el-form-item label="角色">
          <el-checkbox-group v-model="createForm.roles">
            <el-checkbox v-for="r in roles" :key="r.code" :value="r.code">{{ r.name }}</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item>
          <el-checkbox v-model="createForm.must_change">要求首次登录修改口令</el-checkbox>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="submitCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- 编辑角色 -->
    <el-dialog v-model="rolesVisible" :title="`调整角色 - ${editing?.username || ''}`" width="400px" append-to-body>
      <el-checkbox-group v-model="editRoles">
        <el-checkbox v-for="r in roles" :key="r.code" :value="r.code" class="au-role-line">
          {{ r.name }} <span class="au-role-desc">{{ r.description }}</span>
        </el-checkbox>
      </el-checkbox-group>
      <template #footer>
        <el-button @click="rolesVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="submitRoles">保存</el-button>
      </template>
    </el-dialog>

    <!-- 新建令牌 -->
    <el-dialog v-model="tokenCreateVisible" title="新建接口令牌" width="440px" append-to-body>
      <el-form label-width="82px">
        <el-form-item label="名称">
          <el-input v-model="tokenForm.name" placeholder="用途标识，如 SIEM-ingest" />
        </el-form-item>
        <el-form-item label="权限">
          <el-checkbox-group v-model="tokenForm.scopes">
            <el-checkbox v-for="s in allowedScopes" :key="s" :value="s">{{ s }}</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="有效期">
          <el-input-number v-model="tokenForm.expires_days" :min="1" :max="3650" controls-position="right" />
          <span class="au-hint">天，默认 90 天，最长 3650 天</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="tokenCreateVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="submitCreateToken">创建</el-button>
      </template>
    </el-dialog>

    <!-- 一次性展示明文令牌 -->
    <el-dialog v-model="tokenRevealVisible" title="令牌已创建" width="480px" append-to-body :close-on-click-modal="false">
      <el-alert type="warning" :closable="false" show-icon title="请立即复制保存，此明文令牌仅显示这一次" />
      <div class="au-token-reveal">
        <code>{{ newToken }}</code>
      </div>
      <p class="au-hint">调用方式：请求头 <code>Authorization: Bearer &lt;令牌&gt;</code> 或 <code>X-API-Token: &lt;令牌&gt;</code></p>
      <template #footer>
        <el-button type="primary" @click="copyToken">复制令牌</el-button>
        <el-button @click="tokenRevealVisible = false">我已保存</el-button>
      </template>
    </el-dialog>
  </el-drawer>
</template>

<script setup>
import { ref, reactive, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import {
  listAuthUsers, createAuthUser, updateAuthUser, resetAuthUserPassword,
  listApiTokens, createApiToken, revokeApiToken,
  getRolePermissions, setRolePermissions,
} from '../api'
import { peekSessionResume } from '../utils/sessionResume'
import { auth } from '../store/auth'

defineProps({ modelValue: { type: Boolean, default: false } })
const emit = defineEmits(['update:modelValue'])

const activeTab = ref('users')

// ---- 账号 ----
const users = ref([])
const roles = ref([])
const loading = ref(false)
const submitting = ref(false)

const createVisible = ref(false)
const createForm = reactive({ username: '', display_name: '', password: '', roles: [], must_change: true })

const rolesVisible = ref(false)
const editing = ref(null)
const editRoles = ref([])

// ---- 令牌 ----
const tokens = ref([])
const allowedScopes = ref([])
const tokenLoading = ref(false)
const tokenCreateVisible = ref(false)
const tokenForm = reactive({ name: '', scopes: ['alert.create'], expires_days: 90 })
const tokenRevealVisible = ref(false)
const newToken = ref('')

// ---- 角色权限矩阵（列复用 roles ref） ----
const catalog = ref([])
const editMatrix = reactive({})
const permLoading = ref(false)
const permSaving = ref(false)
const adminOnlyPermissions = new Set(['alert.delete', 'system.manage', 'data.clear'])
let pendingResume = null

function captureSessionResume(event) {
  const merge = event?.detail?.mergeViewState
  if (typeof merge !== 'function') return
  const matrix = {}
  for (const [role, values] of Object.entries(editMatrix)) {
    matrix[role] = { ...values }
  }
  merge.call(event.detail, 'admin', {
    activeTab: activeTab.value,
    createOpen: createVisible.value,
    createForm: {
      username: createForm.username,
      display_name: createForm.display_name,
      roles: [...createForm.roles],
      must_change: createForm.must_change,
    },
    rolesOpen: rolesVisible.value,
    editingUserId: editing.value?.id || '',
    editRoles: [...editRoles.value],
    tokenCreateOpen: tokenCreateVisible.value,
    tokenForm: {
      name: tokenForm.name,
      scopes: [...tokenForm.scopes],
      expires_days: tokenForm.expires_days,
    },
    permissionMatrix: matrix,
  })
}

function restoreSessionResume() {
  const state = peekSessionResume(auth.username)?.viewState?.admin
  if (state) pendingResume = state
}

function applyPendingResume() {
  const state = pendingResume
  if (!state) return
  if (['users', 'tokens', 'perms'].includes(state.activeTab)) activeTab.value = state.activeTab
  if (state.createForm) {
    createForm.username = String(state.createForm.username || '')
    createForm.display_name = String(state.createForm.display_name || '')
    createForm.password = ''
    createForm.roles = Array.isArray(state.createForm.roles) ? state.createForm.roles.map(String) : []
    createForm.must_change = state.createForm.must_change !== false
  }
  createVisible.value = !!state.createOpen
  if (state.editingUserId) {
    editing.value = users.value.find(item => String(item.id) === String(state.editingUserId)) || null
    editRoles.value = Array.isArray(state.editRoles) ? state.editRoles.map(String) : []
    rolesVisible.value = !!state.rolesOpen && !!editing.value
  }
  if (state.tokenForm) {
    tokenForm.name = String(state.tokenForm.name || '')
    tokenForm.scopes = Array.isArray(state.tokenForm.scopes) ? state.tokenForm.scopes.map(String) : []
    tokenForm.expires_days = Number(state.tokenForm.expires_days) || 90
  }
  tokenCreateVisible.value = !!state.tokenCreateOpen
  if (state.permissionMatrix && typeof state.permissionMatrix === 'object') {
    for (const [role, values] of Object.entries(state.permissionMatrix)) {
      if (!editMatrix[role] || !values || typeof values !== 'object') continue
      for (const [permission, enabled] of Object.entries(values)) {
        if (permission in editMatrix[role]) editMatrix[role][permission] = !!enabled
      }
    }
  }
  pendingResume = null
}

function fmt(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return isNaN(d) ? iso : d.toLocaleString()
}
function statusLabel(s) { return { active: '正常', disabled: '停用', locked: '锁定' }[s] || s }
function statusType(s) { return { active: 'success', disabled: 'info', locked: 'warning' }[s] || 'info' }

async function onOpen() {
  await Promise.all([loadUsers(), loadTokens(), loadPerms()])
  applyPendingResume()
}

async function loadPerms() {
  permLoading.value = true
  try {
    const res = await getRolePermissions()
    catalog.value = res.data.catalog || []
    roles.value = res.data.roles || []
    const matrix = res.data.matrix || {}
    for (const r of roles.value) {
      const have = new Set(matrix[r.code] || [])
      editMatrix[r.code] = {}
      for (const p of catalog.value) editMatrix[r.code][p.code] = have.has(p.code)
    }
  } catch (e) {
    ElMessage.error(e.message || '加载角色权限失败')
  } finally {
    permLoading.value = false
  }
}

async function savePerms() {
  permSaving.value = true
  try {
    for (const r of roles.value) {
      if (r.code === 'admin') continue
      const perms = catalog.value.filter((p) => editMatrix[r.code] && editMatrix[r.code][p.code]).map((p) => p.code)
      await setRolePermissions(r.code, perms)
    }
    ElMessage.success('角色权限已保存并立即生效')
    await loadPerms()
  } catch (e) {
    ElMessage.error(e.message || '保存失败')
  } finally {
    permSaving.value = false
  }
}

async function loadUsers() {
  loading.value = true
  try {
    const res = await listAuthUsers()
    users.value = res.data.users || []
    roles.value = res.data.roles || []
  } catch (e) {
    ElMessage.error(e.message || '加载账号失败')
  } finally {
    loading.value = false
  }
}

function openCreate() {
  createForm.username = ''
  createForm.display_name = ''
  createForm.password = ''
  createForm.roles = ['analyst']
  createForm.must_change = true
  createVisible.value = true
}

async function submitCreate() {
  if (!createForm.username.trim()) return ElMessage.warning('请输入用户名')
  if (createForm.password.length < 12) return ElMessage.warning('初始口令至少 12 位')
  if (!createForm.roles.length) return ElMessage.warning('请至少选择一个角色')
  submitting.value = true
  try {
    await createAuthUser({ ...createForm })
    ElMessage.success('账号已创建')
    createVisible.value = false
    await loadUsers()
  } catch (e) {
    ElMessage.error(e.message || '创建失败')
  } finally {
    submitting.value = false
  }
}

function openRoles(row) {
  editing.value = row
  editRoles.value = (row.roles || []).map((r) => r.code)
  rolesVisible.value = true
}

async function submitRoles() {
  if (!editRoles.value.length) return ElMessage.warning('请至少选择一个角色')
  submitting.value = true
  try {
    await updateAuthUser(editing.value.id, { roles: editRoles.value })
    ElMessage.success('角色已更新（该用户需重新登录生效）')
    rolesVisible.value = false
    await loadUsers()
  } catch (e) {
    ElMessage.error(e.message || '更新失败')
  } finally {
    submitting.value = false
  }
}

async function toggleStatus(row) {
  const next = row.status === 'active' ? 'disabled' : 'active'
  try {
    await updateAuthUser(row.id, { status: next })
    ElMessage.success(next === 'active' ? '已启用' : '已停用')
    await loadUsers()
  } catch (e) {
    ElMessage.error(e.message || '操作失败')
  }
}

async function resetPassword(row) {
  try {
    const { value } = await ElMessageBox.prompt(`为 ${row.username} 设置新口令（至少 12 位）`, '重置口令', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      inputType: 'password',
      inputValidator: (v) => (v && v.length >= 12) || '口令至少 12 位',
    })
    await resetAuthUserPassword(row.id, value)
    ElMessage.success('口令已重置（该用户需用新口令登录并再次修改）')
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e.message || '重置失败')
  }
}

// ---- 令牌逻辑 ----
function tokenStatusLabel(row) {
  if (row.revoked) return '已吊销'
  if (row.expires_at && new Date(row.expires_at) < new Date()) return '已过期'
  return '有效'
}
function tokenStatusType(row) {
  if (row.revoked) return 'info'
  if (row.expires_at && new Date(row.expires_at) < new Date()) return 'warning'
  return 'success'
}

async function loadTokens() {
  tokenLoading.value = true
  try {
    const res = await listApiTokens()
    tokens.value = res.data.tokens || []
    allowedScopes.value = res.data.allowed_scopes || []
  } catch (e) {
    ElMessage.error(e.message || '加载令牌失败')
  } finally {
    tokenLoading.value = false
  }
}

function openCreateToken() {
  tokenForm.name = ''
  tokenForm.scopes = ['alert.create']
  tokenForm.expires_days = 90
  tokenCreateVisible.value = true
}

async function submitCreateToken() {
  if (!tokenForm.name.trim()) return ElMessage.warning('请输入令牌名称')
  if (!tokenForm.scopes.length) return ElMessage.warning('请至少选择一个权限')
  submitting.value = true
  try {
    const payload = {
      name: tokenForm.name.trim(),
      scopes: tokenForm.scopes,
      expires_days: tokenForm.expires_days,
    }
    const res = await createApiToken(payload)
    newToken.value = res.data.token
    tokenCreateVisible.value = false
    tokenRevealVisible.value = true
    await loadTokens()
  } catch (e) {
    ElMessage.error(e.message || '创建失败')
  } finally {
    submitting.value = false
  }
}

async function copyToken() {
  try {
    await navigator.clipboard.writeText(newToken.value)
    ElMessage.success('已复制到剪贴板')
  } catch (e) {
    ElMessage.warning('复制失败，请手动选择复制')
  }
}

async function revokeToken(row) {
  try {
    await ElMessageBox.confirm(`确认吊销令牌「${row.name}」？吊销后使用该令牌的自动化推送将立即失败。`, '吊销令牌', {
      type: 'warning', confirmButtonText: '吊销', cancelButtonText: '取消',
    })
    await revokeApiToken(row.id)
    ElMessage.success('已吊销')
    await loadTokens()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e.message || '吊销失败')
  }
}

onMounted(() => {
  window.addEventListener('capture-session-resume', captureSessionResume)
  restoreSessionResume()
})
onBeforeUnmount(() => window.removeEventListener('capture-session-resume', captureSessionResume))
</script>

<style scoped>
.au-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.au-hint {
  color: var(--text-muted, #8B92A0);
  font-size: 12px;
}
.au-role-tag {
  margin-right: 4px;
}
.au-role-line {
  display: flex;
  width: 100%;
  margin-bottom: 6px;
}
.au-role-desc {
  color: var(--text-muted, #8B92A0);
  font-size: 12px;
  margin-left: 6px;
}
.au-token-reveal {
  margin: 12px 0;
  padding: 10px 12px;
  background: var(--bg-secondary, #F5F7FA);
  border: 1px solid var(--border, #d3dae6);
  border-radius: 6px;
  word-break: break-all;
  font-size: 13px;
}
.au-matrix-wrap { overflow-x: auto; }
.au-matrix {
  border-collapse: collapse;
  width: 100%;
  font-size: 13px;
}
.au-matrix th, .au-matrix td {
  border: 1px solid var(--border-light, #E8EDF3);
  padding: 6px 8px;
  text-align: center;
}
.au-matrix thead th {
  background: var(--bg-secondary, #F5F7FA);
  font-weight: 600;
  position: sticky;
  top: 0;
}
.au-matrix .au-perm-col {
  text-align: left;
  white-space: nowrap;
}
.au-cat {
  display: inline-block;
  min-width: 34px;
  margin-right: 8px;
  padding: 0 6px;
  border-radius: 10px;
  background: var(--primary-light, #D9E8FA);
  color: var(--primary, #006DE0);
  font-size: 11px;
}
.au-risk {
  margin-left: 6px;
  color: var(--el-color-danger);
  font-size: 11px;
  font-weight: 400;
}
.au-check-cell { width: 90px; }
</style>
