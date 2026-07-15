<template>
  <!-- 登录等公开页：仅渲染路由内容，不套工作台外壳 -->
  <router-view v-if="isPublicRoute" />

  <div v-else class="app-container">
    <!-- 主内容区 -->
    <div class="main">
      <!-- 顶部栏 -->
      <header class="header">
        <div class="breadcrumb">
          <span class="breadcrumb-icon">
            <el-icon :size="16"><Warning /></el-icon>
          </span>
          <span class="breadcrumb-text">研判分析工作台</span>
        </div>
        <div class="header-actions">
          <el-tooltip content="刷新数据" placement="bottom">
            <button class="icon-btn" @click="refreshData" :disabled="loading">
              <el-icon :size="16" :class="{ 'is-loading': loading }"><Refresh /></el-icon>
            </button>
          </el-tooltip>

          <el-dropdown trigger="click" @command="onUserCommand">
            <button class="user-btn">
              <el-icon :size="15"><UserFilled /></el-icon>
              <span class="user-name">{{ auth.displayName }}</span>
              <span v-if="primaryRoleName" class="user-role">{{ primaryRoleName }}</span>
              <el-icon :size="12"><ArrowDown /></el-icon>
            </button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="changePassword">
                  <el-icon><Key /></el-icon>修改口令
                </el-dropdown-item>
                <el-dropdown-item v-if="auth.hasPerm('audit.view')" command="auditLog">
                  <el-icon><Document /></el-icon>审计中心
                </el-dropdown-item>
                <el-dropdown-item v-if="auth.hasPerm('system.manage')" command="adminUsers">
                  <el-icon><Setting /></el-icon>账号管理
                </el-dropdown-item>
                <el-dropdown-item command="logout" divided>
                  <el-icon><SwitchButton /></el-icon>退出登录
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>

      <!-- 内容区 -->
      <main class="content">
        <template v-if="!loading">
          <keep-alive>
            <router-view @refresh="refreshData" />
          </keep-alive>
        </template>
        <div v-else class="loading-container">
          <div class="loading-spinner"></div>
          <p>加载中...</p>
        </div>
      </main>
    </div>

    <!-- 修改口令 -->
    <el-dialog v-model="pwVisible" title="修改口令" width="400px">
      <el-form label-width="82px">
        <el-form-item label="当前口令">
          <el-input v-model="pwForm.old" type="password" show-password autocomplete="current-password" />
        </el-form-item>
        <el-form-item label="新口令">
          <el-input v-model="pwForm.neo" type="password" show-password autocomplete="new-password" placeholder="至少 8 位" />
        </el-form-item>
        <el-form-item label="确认新口令">
          <el-input v-model="pwForm.confirm" type="password" show-password autocomplete="new-password" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwVisible = false">取消</el-button>
        <el-button type="primary" :loading="pwLoading" @click="submitChangePassword">保存</el-button>
      </template>
    </el-dialog>

    <AdminUsers v-model="adminVisible" />
    <AuditLog v-model="auditVisible" />
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  Refresh, Warning, UserFilled, ArrowDown, Key, Setting, SwitchButton, Document,
} from '@element-plus/icons-vue'
import { auth } from './store/auth'
import { authChangePassword } from './api'
import AdminUsers from './components/AdminUsers.vue'
import AuditLog from './components/AuditLog.vue'

const route = useRoute()
const router = useRouter()
const loading = ref(false)

const isPublicRoute = computed(() => !!route.meta.public)
const primaryRoleName = computed(() => auth.user?.roles?.[0]?.name || '')

const refreshData = () => {
  window.dispatchEvent(new CustomEvent('refresh-data'))
}

// ---- 用户菜单 ----
const pwVisible = ref(false)
const pwLoading = ref(false)
const pwForm = reactive({ old: '', neo: '', confirm: '' })
const adminVisible = ref(false)
const auditVisible = ref(false)

function onUserCommand(cmd) {
  if (cmd === 'changePassword') {
    pwForm.old = ''
    pwForm.neo = ''
    pwForm.confirm = ''
    pwVisible.value = true
  } else if (cmd === 'adminUsers') {
    adminVisible.value = true
  } else if (cmd === 'auditLog') {
    auditVisible.value = true
  } else if (cmd === 'logout') {
    doLogout()
  }
}

async function doLogout() {
  await auth.logout()
  router.push('/login')
}

async function submitChangePassword() {
  if (pwForm.neo.length < 8) return ElMessage.warning('新口令至少 8 位')
  if (pwForm.neo !== pwForm.confirm) return ElMessage.warning('两次输入的新口令不一致')
  pwLoading.value = true
  try {
    await authChangePassword(pwForm.old, pwForm.neo)
    ElMessage.success('口令已更新')
    pwVisible.value = false
  } catch (e) {
    ElMessage.error(e.message || '修改失败')
  } finally {
    pwLoading.value = false
  }
}

// ---- 会话失效 -> 回登录页 ----
function handleUnauthorized() {
  if (route.meta.public) return
  auth._clear()
  ElMessage.warning('登录已失效，请重新登录')
  router.push({ path: '/login', query: { redirect: route.fullPath } })
}
onMounted(() => window.addEventListener('auth-unauthorized', handleUnauthorized))
onBeforeUnmount(() => window.removeEventListener('auth-unauthorized', handleUnauthorized))
</script>

<style>
/* ===== Design System - Global Styles ===== */
:root {
  /* Brand Colors */
  --primary: #006DE0;
  --primary-hover: #0058B5;
  --primary-light: #D9E8FA;
  --accent: #F04E98;
  --accent-light: #FDE8F2;

  /* Neutrals */
  --bg-primary: #FAFBFD;
  --bg-secondary: #F5F7FA;
  --bg-surface: #FFFFFF;
  --border: #D3DAE6;
  --border-light: #E8EDF3;

  /* Text */
  --text-primary: #1B1D21;
  --text-secondary: #5A6069;
  --text-muted: #8B92A0;

  /* Status */
  --success: #017D73;
  --success-light: #D6FAF2;
  --warning: #D6A000;
  --warning-light: #FFF8DB;
  --danger: #BD271E;
  --danger-light: #FDECEB;

  /* Sizing */
  --header-height: 48px;
  --radius: 6px;
  --radius-sm: 4px;

  /* Shadows */
  --shadow-sm: 0 1px 3px rgba(0,0,0,0.08);
  --shadow-md: 0 2px 8px rgba(0,0,0,0.1);
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  background: var(--bg-primary);
  color: var(--text-primary);
  font-size: 14px;
  line-height: 1.5;
}

/* ===== Override Element Plus Theme ===== */
:root {
  --el-color-primary: #006DE0;
  --el-color-primary-light-3: #4D9CE8;
  --el-color-primary-light-5: #80B8F0;
  --el-color-primary-light-7: #B3D5F5;
  --el-color-primary-light-9: #E8F1FC;
  --el-color-primary-dark-2: #0058B5;
  --el-color-success: #017D73;
  --el-color-warning: #D6A000;
  --el-color-danger: #BD271E;
  --el-border-radius-base: 4px;
  --el-font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --el-fill-color-light: #F5F7FA;
}

/* ===== App Layout ===== */
.app-container {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

.main {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-width: 0;
}

/* ===== Header ===== */
.header {
  height: var(--header-height);
  background: var(--bg-surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
  flex-shrink: 0;
}

.breadcrumb {
  display: flex;
  align-items: center;
  gap: 8px;
}

.breadcrumb-icon {
  display: flex;
  align-items: center;
  color: var(--primary);
}

.breadcrumb-text {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-primary);
  letter-spacing: -0.01em;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.icon-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-surface);
  cursor: pointer;
  color: var(--text-secondary);
  transition: all 0.15s ease;
}

.icon-btn:hover {
  background: var(--bg-secondary);
  color: var(--text-primary);
}

.icon-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.icon-btn .is-loading {
  animation: rotating 1.5s linear infinite;
}

/* ===== User menu ===== */
.user-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  height: 32px;
  padding: 0 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-surface);
  cursor: pointer;
  color: var(--text-secondary);
  transition: all 0.15s ease;
}

.user-btn:hover {
  background: var(--bg-secondary);
  color: var(--text-primary);
}

.user-btn .user-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

.user-btn .user-role {
  font-size: 11px;
  font-weight: 600;
  color: var(--primary);
  background: var(--primary-light);
  padding: 1px 6px;
  border-radius: 10px;
}

@keyframes rotating {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* ===== Content ===== */
.content {
  flex: 1;
  overflow-y: auto;
  background: var(--bg-primary);
  padding: 20px;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 300px;
  color: var(--text-muted);
  gap: 12px;
}

.loading-spinner {
  width: 28px;
  height: 28px;
  border: 3px solid var(--border);
  border-top-color: var(--primary);
  border-radius: 50%;
  animation: rotating 0.8s linear infinite;
}

/* ===== Panel (replaces el-card) ===== */
.panel {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}

.panel-header {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-light);
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 44px;
}

.panel-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
  display: flex;
  align-items: center;
  gap: 8px;
}

.panel-body {
  padding: 16px;
}

/* ===== Table Style Overrides ===== */
.el-table {
  --el-table-border-color: var(--border-light);
  --el-table-header-bg-color: var(--bg-secondary);
  --el-table-row-hover-bg-color: var(--primary-light);
  --el-table-bg-color: var(--bg-surface);
  font-size: 13px;
}

.el-table th.el-table__cell {
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  color: var(--text-secondary);
}

.el-table td.el-table__cell {
  padding: 8px 0;
}

/* ===== Tag/Badge ===== */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.02em;
}

.badge--success {
  background: var(--success-light);
  color: var(--success);
}

.badge--danger {
  background: var(--danger-light);
  color: var(--danger);
}

.badge--primary {
  background: var(--primary-light);
  color: var(--primary);
}

.badge--warning {
  background: var(--warning-light);
  color: var(--warning);
}

.badge--neutral {
  background: var(--bg-secondary);
  color: var(--text-secondary);
}

/* ===== Override el-tag ===== */
.el-tag {
  border-radius: 12px !important;
  font-size: 11px !important;
  font-weight: 600 !important;
  padding: 0 8px !important;
  height: 22px !important;
  line-height: 22px !important;
}

/* ===== Button Override ===== */
.el-button--primary {
  --el-button-bg-color: var(--primary);
  --el-button-border-color: var(--primary);
  --el-button-hover-bg-color: var(--primary-hover);
  --el-button-hover-border-color: var(--primary-hover);
}

/* ===== Input Override ===== */
.el-input__wrapper {
  border-radius: var(--radius-sm) !important;
}

.el-input__wrapper:hover {
  box-shadow: 0 0 0 1px var(--primary) inset !important;
}

.el-input__wrapper.is-focus {
  box-shadow: 0 0 0 2px var(--primary) inset !important;
}

/* ===== Dialog Override ===== */
.el-dialog {
  border-radius: var(--radius) !important;
}

.el-dialog__header {
  border-bottom: 1px solid var(--border-light);
  padding: 16px 20px !important;
}

.el-dialog__title {
  font-weight: 600 !important;
  font-size: 15px !important;
}

/* ===== Alert Override ===== */
.el-alert {
  border-radius: var(--radius-sm) !important;
}

/* ===== Scrollbar ===== */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: transparent;
}

::-webkit-scrollbar-thumb {
  background: #C1C7D0;
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: #A0A8B4;
}
</style>
