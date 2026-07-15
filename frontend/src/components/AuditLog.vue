<template>
  <el-drawer :model-value="modelValue" title="审计中心" size="60%" :append-to-body="true"
             @update:model-value="(v) => emit('update:modelValue', v)" @open="onOpen">
    <!-- 完整性状态 -->
    <div class="al-integrity" :class="integrityClass">
      <el-icon><component :is="integrity && integrity.ok ? 'CircleCheck' : 'Warning'" /></el-icon>
      <span v-if="!integrity">审计完整性校验中…</span>
      <span v-else-if="integrity.ok">
        审计链完整性校验通过（已校验 {{ integrity.checked }} 条{{ integrity.skipped_legacy ? '，另有 ' + integrity.skipped_legacy + ' 条历史未链式存证' : '' }}）
      </span>
      <span v-else>
        ⚠ 审计链校验未通过，疑似被篡改：断裂于「{{ integrity.broken_at && integrity.broken_at.action }} · {{ fmt(integrity.broken_at && integrity.broken_at.created_at) }}」
      </span>
    </div>

    <!-- 过滤条 -->
    <div class="al-filters">
      <el-input v-model="filters.actor" size="small" placeholder="操作人" clearable class="al-f" />
      <el-select v-model="filters.action" size="small" placeholder="动作" clearable filterable class="al-f">
        <el-option v-for="a in actionOptions" :key="a.value" :label="a.label" :value="a.value" />
      </el-select>
      <el-input v-model="filters.keyword" size="small" placeholder="关键词（对象ID/内容）" clearable class="al-f-wide" @keyup.enter="load" />
      <el-date-picker v-model="filters.range" type="datetimerange" size="small" range-separator="至"
                      start-placeholder="开始" end-placeholder="结束" class="al-f-range" />
      <el-button size="small" type="primary" @click="load">查询</el-button>
      <el-button size="small" @click="resetFilters">重置</el-button>
      <el-button size="small" @click="exportCsv">导出 CSV</el-button>
    </div>

    <el-table :data="items" size="small" v-loading="loading" style="width: 100%" max-height="60vh">
      <el-table-column label="时间" width="170">
        <template #default="{ row }">{{ fmt(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="操作人" width="130">
        <template #default="{ row }">
          <span>{{ row.actor || '-' }}</span>
          <el-tag v-if="!row.actor_user_id" size="small" type="info" class="al-tag">非账号</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="动作" width="130">
        <template #default="{ row }">
          <el-tag size="small" :type="actionType(row.action)">{{ actionLabel(row.action) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="对象" min-width="140">
        <template #default="{ row }">
          <span class="al-target">{{ row.target_type }}</span>
          <span class="al-target-id">{{ row.target_id || '' }}</span>
        </template>
      </el-table-column>
      <el-table-column label="摘要" min-width="220">
        <template #default="{ row }"><span class="al-summary">{{ summarize(row) }}</span></template>
      </el-table-column>
      <el-table-column label="存证" width="70">
        <template #default="{ row }">
          <el-tag size="small" :type="row.entry_hash ? 'success' : 'info'">{{ row.entry_hash ? '链式' : '历史' }}</el-tag>
        </template>
      </el-table-column>
    </el-table>
    <div class="al-hint">最多显示最近 {{ limit }} 条；如需更早记录请用过滤条件或导出 CSV。</div>
  </el-drawer>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { CircleCheck, Warning } from '@element-plus/icons-vue'
import { getIncidentAudit, verifyIncidentAudit, exportIncidentAuditCsv } from '../api'

defineProps({ modelValue: { type: Boolean, default: false } })
const emit = defineEmits(['update:modelValue'])

const items = ref([])
const loading = ref(false)
const integrity = ref(null)
const limit = 300
const filters = reactive({ actor: '', action: '', keyword: '', range: null })

const ACTION_LABELS = {
  login: '登录', logout: '登出', login_failed: '登录失败', permission_denied: '鉴权拒绝',
  create_user: '新建账号', set_user_roles: '调整角色', set_user_status: '账号启停',
  admin_reset_password: '重置口令', change_password: '修改口令',
  create_api_token: '创建令牌', revoke_api_token: '吊销令牌',
  create_alert: '录入告警', update_alert: '编辑告警', delete_alert: '删除告警',
  set_handlers: '指派处理人', assign_handler: '指派处理人',
  reject_alert: '驳回重判', reopen_alert: '重新研判', add_note: '研判记录',
  upload_attachment: '上传附件', clear_all: '清空数据',
  batch_assign: '批量分派', batch_status: '批量改状态', batch_note: '批量备注', batch_severity: '批量改等级',
}
const actionOptions = computed(() =>
  Object.entries(ACTION_LABELS).map(([value, label]) => ({ value, label })))

function actionLabel(a) { return ACTION_LABELS[a] || a }
function actionType(a) {
  if (a === 'permission_denied' || a === 'login_failed' || a === 'delete_alert' || a === 'clear_all') return 'danger'
  if (a === 'login' || a === 'create_alert') return 'success'
  if (a && a.startsWith('set_user') || a === 'create_user' || a && a.indexOf('token') >= 0) return 'warning'
  return 'info'
}
function fmt(iso) {
  if (!iso) return '-'
  const d = new Date(iso)
  return isNaN(d) ? iso : d.toLocaleString()
}
function summarize(row) {
  const a = row.action
  const after = row.after_data || {}
  const before = row.before_data || {}
  if (a === 'permission_denied') return `${after.method || ''} ${after.path || ''}`.trim()
  if (a === 'login' || a === 'login_failed') return after.ip ? `IP ${after.ip}` : ''
  if (a === 'set_user_roles') return `角色: ${(after.roles || []).join('、')}`
  if (a === 'set_user_status') return `状态: ${after.status || ''}`
  if (a === 'create_user') return `用户: ${after.username || ''}`
  if (a === 'create_api_token') return `令牌: ${after.name || ''}`
  if (a === 'create_alert' || a === 'update_alert') return after.title || after.conclusion_label || ''
  if (a === 'delete_alert') return before.title || ''
  if (a === 'set_handlers' || a === 'assign_handler') return `处理人: ${(after.handlers || [after.handler]).filter(Boolean).join('、')}`
  return ''
}

const integrityClass = computed(() => {
  if (!integrity.value) return 'al-integrity--pending'
  return integrity.value.ok ? 'al-integrity--ok' : 'al-integrity--bad'
})

function queryParams() {
  const p = { limit }
  if (filters.actor) p.actor = filters.actor
  if (filters.action) p.action = filters.action
  if (filters.keyword) p.keyword = filters.keyword
  if (filters.range && filters.range.length === 2) {
    p.start = new Date(filters.range[0]).toISOString()
    p.end = new Date(filters.range[1]).toISOString()
  }
  return p
}

async function onOpen() {
  await load()
  verify()
}

async function load() {
  loading.value = true
  try {
    const res = await getIncidentAudit(queryParams())
    items.value = res.data.items || []
  } catch (e) {
    ElMessage.error(e.message || '加载审计失败')
  } finally {
    loading.value = false
  }
}

async function verify() {
  try {
    const res = await verifyIncidentAudit()
    integrity.value = res.data
  } catch (e) {
    integrity.value = { ok: false, broken_at: null }
  }
}

function resetFilters() {
  filters.actor = ''
  filters.action = ''
  filters.keyword = ''
  filters.range = null
  load()
}

async function exportCsv() {
  try {
    const csv = await exportIncidentAuditCsv(queryParams())
    const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'audit-log.csv'
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    ElMessage.error(e.message || '导出失败')
  }
}
</script>

<style scoped>
.al-integrity {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
  margin-bottom: 12px;
}
.al-integrity--ok { background: var(--success-light, #D6FAF2); color: var(--success, #017D73); }
.al-integrity--bad { background: var(--danger-light, #FDECEB); color: var(--danger, #BD271E); }
.al-integrity--pending { background: var(--bg-secondary, #F5F7FA); color: var(--text-secondary, #5A6069); }
.al-filters {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.al-f { width: 130px; }
.al-f-wide { width: 200px; }
.al-f-range { width: 340px; }
.al-tag { margin-left: 4px; }
.al-target { font-weight: 600; }
.al-target-id { color: var(--text-muted, #8B92A0); margin-left: 6px; font-size: 12px; }
.al-summary { color: var(--text-secondary, #5A6069); font-size: 12px; }
.al-hint { color: var(--text-muted, #8B92A0); font-size: 12px; margin-top: 8px; }
</style>
