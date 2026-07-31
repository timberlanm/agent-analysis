<script>
export default { name: 'Incident' }
</script>

<template>
  <div class="analysis-page">
    <div class="ops-collapse" :class="{ 'ops-collapse--hidden': opsHidden }">
    <div class="operations-panel kibana-panel">
      <div class="operations-header">
        <div class="panel-title ops-title">运营概览</div>
        <div class="ops-compact">
          <span>总数 <strong>{{ stats.total || 0 }}</strong></span>
          <span>待分配 <strong>{{ stats.by_status?.['待分配'] || 0 }}</strong></span>
          <span>研判中 <strong>{{ stats.by_status?.['研判中'] || 0 }}</strong></span>
          <span>应急响应中 <strong>{{ stats.by_status?.['应急响应中'] || 0 }}</strong></span>
          <span>已完成 <strong>{{ stats.by_status?.['已完成'] || 0 }}</strong></span>
          <span class="ops-compact-sep">近{{ operationDays }}天</span>
          <span>新增 <strong>{{ operations.summary?.created || 0 }}</strong></span>
          <span>关闭 <strong>{{ operations.summary?.closed || 0 }}</strong></span>
          <span>平均关闭 <strong>{{ operations.summary?.avg_close_hours || 0 }}h</strong></span>
        </div>
        <div class="operations-actions">
          <el-select v-model="operationDays" size="small" @change="loadOperations">
            <el-option :value="7" label="近 7 天" />
            <el-option :value="30" label="近 30 天" />
            <el-option :value="90" label="近 90 天" />
          </el-select>
          <el-button v-if="hasPerm('export')" size="small" @click="exportOperationsCsv">
            <el-icon><Download /></el-icon>导出报表
          </el-button>
        </div>
      </div>
    </div>
    </div>

    <div class="analysis-main">
      <section
        class="analysis-list kibana-panel"
        :class="{ 'list-dragging': isListDragging }"
        @dragenter.prevent="onListDragEnter"
        @dragover.prevent
        @dragleave.prevent="onListDragLeave"
        @drop.prevent="handleListDrop"
      >
        <div v-if="isListDragging" class="list-drop-overlay">
          <div class="list-drop-card">
            <el-icon><Upload /></el-icon>
            <div>松开以根据截图快速创建告警</div>
            <small>支持一次拖入多张截图，每张生成一条告警</small>
          </div>
        </div>
        <div class="panel-header">
          <div class="panel-heading-row">
            <div class="panel-title">告警队列</div>
          </div>
          <div class="panel-actions">
            <el-input
              v-model="filters.keyword"
              size="small"
              clearable
              placeholder="搜索告警编号 / IP / 主机 / Hash / 标题"
              class="filter-keyword"
              @keyup.enter="loadAlerts"
              @clear="loadAlerts"
            >
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
            <el-select v-model="filters.status" size="small" clearable placeholder="状态" @change="loadAlerts">
              <el-option v-for="item in statusOptions" :key="item.value" :label="item.label" :value="item.value" />
            </el-select>
            <el-select v-model="filters.source_category" size="small" clearable placeholder="设备类型" @change="loadAlerts">
              <el-option v-for="item in templateOptions" :key="item.value" :label="item.label" :value="item.value" />
            </el-select>
            <el-input
              v-model="filters.reporter"
              size="small"
              clearable
              placeholder="上报人"
              class="filter-person"
              @keyup.enter="loadAlerts"
              @clear="loadAlerts"
            />
            <el-input
              v-model="filters.owner"
              size="small"
              clearable
              placeholder="处理人"
              class="filter-person"
              @keyup.enter="loadAlerts"
              @clear="loadAlerts"
            />
            <el-button size="small" @click="loadAlerts">查询</el-button>
            <el-button size="small" @click="refreshAll" :loading="loading">
              <el-icon><Refresh /></el-icon>刷新
            </el-button>
            <el-button v-if="hasPerm('alert.create')" size="small" type="primary" @click="openCreate">
              <el-icon><Plus /></el-icon>新建告警
            </el-button>
          </div>
        </div>

        <div v-if="selectedAlertIds.length" class="batch-toolbar">
          <span>已选择 {{ selectedAlertIds.length }} 条</span>
          <el-input v-model="batchForm.owner" size="small" placeholder="处理人" class="batch-owner" />
          <el-button v-if="hasPerm('alert.assign')" size="small" @click="batchAssign" :loading="batchLoading">批量分派</el-button>
          <el-select v-if="hasPerm('alert.status')" v-model="batchForm.status" size="small" placeholder="状态" class="batch-select">
            <el-option v-for="item in statusOptions.filter(option => option.value !== 'closed')" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
          <el-button v-if="hasPerm('alert.status')" size="small" @click="batchChangeStatus" :loading="batchLoading">改状态</el-button>
          <el-button v-if="hasPerm('alert.note')" size="small" @click="batchAddNote" :loading="batchLoading">批量备注</el-button>
        </div>

        <el-table
          ref="alertTableRef"
          :data="alerts"
          height="100%"
          class="alert-table"
          highlight-current-row
          @row-click="handleAlertRowClick"
          @selection-change="handleSelectionChange"
        >
          <el-table-column type="selection" width="42" />
          <el-table-column prop="alert_no" label="告警编号" width="190">
            <template #default="{ row }">
              <button
                class="alert-no"
                :title="`复制告警编号 ${row.alert_no}`"
                @click.stop="copyAlertNo(row.alert_no)"
              >
                {{ row.alert_no || '-' }}
              </button>
            </template>
          </el-table-column>
          <el-table-column prop="title" label="标题" min-width="220">
            <template #default="{ row }">
              <div class="alert-title-cell" :title="row.title">
                <span>{{ row.title || '未命名告警' }}</span>
              </div>
              <div class="muted-line">{{ row.source_category_label || '其他 / 通用' }} · {{ row.source_system || '未知来源' }} · {{ row.alert_type || '未分类' }}</div>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="110">
            <template #default="{ row }">
              <el-tag size="small" :type="statusTag(row.status)">{{ row.status_label || row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="结论" width="110">
            <template #default="{ row }">
              <span class="muted-line">{{ row.conclusion_label || '未定' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="攻击IP" width="140">
            <template #default="{ row }">
              <span>{{ (row.normalized_fields?.source_ip) || '-' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="被攻击IP" width="140">
            <template #default="{ row }">
              <span>{{ (row.normalized_fields?.destination_ip) || '-' }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="created_by" label="上报人" width="110" />
          <el-table-column label="处理人" width="130">
            <template #default="{ row }">{{ (row.handlers || []).join('、') || '-' }}</template>
          </el-table-column>
          <el-table-column label="告警时间" width="160">
            <template #default="{ row }">{{ formatTime(row.occurred_at) }}</template>
          </el-table-column>
          <el-table-column label="上报时间" width="160">
            <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="120" fixed="right">
            <template #default="{ row }">
              <el-tooltip :disabled="row.status !== 'closed'" content="已完成告警不可编辑，请先『重新研判』" placement="top">
                <span>
                  <el-button v-if="hasPerm('alert.edit')" size="small" type="primary" link :disabled="row.status === 'closed'" @click.stop="openEditAlert(row)">编辑</el-button>
                </span>
              </el-tooltip>
              <el-button v-if="hasPerm('alert.assign')" size="small" type="primary" link @click.stop="openAssignDialog(row)">指派</el-button>
            </template>
          </el-table-column>
        </el-table>
      </section>

      <el-dialog
        v-model="detailDialogVisible"
        fullscreen
        destroy-on-close
        :show-close="false"
        class="alert-detail-dialog"
        @opened="bindDetailScroll"
        @closed="unbindDetailScroll"
      >
        <template #header>
          <div class="detail-dialog-header" :class="{ 'is-shrunk': headerShrunk }">
            <div class="detail-dialog-heading">
              <div class="detail-dialog-title">告警研判详情</div>
              <div class="detail-dialog-counter">
                当前筛选结果第 {{ selectedAlertPosition }} 条，共 {{ alerts.length }} 条
              </div>
            </div>
            <div class="detail-navigation">
              <el-button size="small" :disabled="!hasPreviousAlert" @click="openAdjacentAlert(-1)">
                <el-icon><ArrowLeft /></el-icon>上一条
              </el-button>
              <el-button size="small" type="primary" :disabled="!hasNextAlert" @click="openAdjacentAlert(1)">
                下一条<el-icon><ArrowRight /></el-icon>
              </el-button>
              <el-tooltip content="关闭详情" placement="bottom">
                <el-button size="small" circle aria-label="关闭详情" @click="detailDialogVisible = false">
                  <el-icon><Close /></el-icon>
                </el-button>
              </el-tooltip>
            </div>
          </div>
        </template>

        <div v-if="selectedAlert" class="detail-dialog-body">
          <div class="detail-header">
            <div>
              <div class="detail-title">
                <button
                  class="alert-no detail-alert-no"
                  :title="`复制告警编号 ${selectedAlert.alert_no}`"
                  @click="copyAlertNo(selectedAlert.alert_no)"
                >
                  {{ selectedAlert.alert_no || '-' }}
                </button>
                <span :title="selectedAlert.title">{{ selectedAlert.title }}</span>
              </div>
              <div class="detail-meta">
                {{ selectedAlert.source_category_label || '其他 / 通用' }} · {{ selectedAlert.source_system || '未知来源' }} · {{ selectedAlert.alert_type || '未分类' }} · {{ formatTime(selectedAlert.occurred_at) }}
              </div>
            </div>
            <div class="detail-actions">
              <el-tooltip :disabled="!isClosed" content="已完成告警不可编辑，请先『重新研判』" placement="bottom">
                <span>
                  <el-button v-if="hasPerm('alert.edit')" size="small" type="primary" plain :disabled="isClosed" @click="openEditAlert(selectedAlert.id)"><el-icon><Edit /></el-icon>编辑</el-button>
                </span>
              </el-tooltip>
              <el-button v-if="hasPerm('alert.assign')" size="small" type="primary" plain @click="openAssignDialog(selectedAlert)"><el-icon><User /></el-icon>指派</el-button>
              <el-button v-if="selectedAlert.status === 'closed' && hasPerm('alert.reopen')" size="small" type="danger" plain @click="openReopenDialog"><el-icon><RefreshRight /></el-icon>重新研判</el-button>
              <el-button v-if="selectedAlert.status === 'closed' && hasPerm('alert.reject')" size="small" type="warning" plain @click="openRejectDialog"><el-icon><RefreshLeft /></el-icon>驳回重判</el-button>
              <el-button v-if="hasPerm('export')" size="small" @click="exportMarkdown"><el-icon><Download /></el-icon>导出 Markdown</el-button>
              <el-button v-if="hasPerm('alert.delete')" size="small" type="danger" plain @click="removeSelected"><el-icon><Delete /></el-icon>删除</el-button>
            </div>
          </div>

          <div class="detail-card detail-overview">
              <div class="card-title">上报信息</div>
              <el-descriptions :column="3" border size="small">
                <el-descriptions-item label="安全设备">{{ selectedAlert.source_system || '-' }}</el-descriptions-item>
                <el-descriptions-item label="攻击IP">{{ selectedAlert.normalized_fields?.source_ip || '-' }}</el-descriptions-item>
                <el-descriptions-item label="被攻击IP">{{ selectedAlert.normalized_fields?.destination_ip || '-' }}</el-descriptions-item>
                <el-descriptions-item label="上报人">{{ selectedAlert.created_by || '-' }}</el-descriptions-item>
                <el-descriptions-item label="告警时间">{{ formatTime(selectedAlert.occurred_at) }}</el-descriptions-item>
                <el-descriptions-item label="上报时间">{{ formatTime(selectedAlert.created_at) }}</el-descriptions-item>
              </el-descriptions>
            </div>

          <div
            class="evidence-panel"
            :class="{ 'is-dragging': isDragging }"
            @dragover.prevent="isDragging = true"
            @dragleave.prevent="isDragging = false"
            @drop.prevent="handleEvidenceDrop"
          >
            <div class="card-title">
              告警截图 / 证据
              <span v-if="imageAttachments.length" class="template-label">{{ imageAttachments.length }} 张截图</span>
            </div>
            <div class="evidence-uploader">
              <input ref="attachmentInputRef" hidden type="file" multiple @change="handleAttachmentPick" />
              <el-button v-if="hasPerm('attachment.write')" size="small" type="primary" plain @click="attachmentInputRef?.click()">
                <el-icon><Upload /></el-icon>上传 / 粘贴截图
              </el-button>
              <span>设备截图即为研判主依据；可拖拽文件到此、点击上传或 Ctrl+V 粘贴</span>
            </div>
            <div v-if="isDragging" class="evidence-drop-hint">松开鼠标即可上传到本告警</div>
            <div v-if="imageAttachments.length" class="evidence-gallery">
              <div v-for="(att, idx) in imageAttachments" :key="att.id" class="evidence-shot">
                <el-image
                  :src="att.url"
                  :preview-src-list="imageUrls"
                  :initial-index="idx"
                  fit="contain"
                  hide-on-click-modal
                  preview-teleported
                />
                <button
                  class="attachment-delete evidence-shot-delete"
                  :aria-label="`删除截图 ${att.original_name}`"
                  title="删除截图"
                  @click.stop="removeAttachment(att)"
                >
                  <el-icon><Delete /></el-icon>
                </button>
              </div>
            </div>
            <div v-else class="evidence-empty" @click="attachmentInputRef?.click()">
              <el-icon class="evidence-empty-icon"><Upload /></el-icon>
              <div class="evidence-empty-title">把告警截图拖到这里</div>
              <div class="evidence-empty-sub">或 点击此处选择文件 · Ctrl+V 粘贴截图（支持图片 / 日志 / PCAP）</div>
            </div>
            <div v-if="otherAttachments.length" class="evidence-files">
              <div
                v-for="att in otherAttachments"
                :key="att.id"
                class="evidence-file-chip"
                :class="{ 'is-missing': att.file_available === false }"
                :title="att.file_available === false
                  ? `${att.original_name}（源文件缺失）`
                  : `${att.original_name}（点击下载）`"
                @click="openAttachment(att)"
              >
                <el-icon><Document /></el-icon>
                <span>{{ att.original_name }}</span>
                <small>{{ att.file_available === false ? '文件缺失' : attachmentTypeLabel(att.file_type) }}</small>
                <button class="attachment-delete" @click.stop="removeAttachment(att)"><el-icon><Delete /></el-icon></button>
              </div>
            </div>
          </div>

          <div v-if="alertDetailRows.length || selectedAlert.description" class="detail-description alert-detail-block">
            <div class="detail-description-title">告警详情</div>
            <div v-if="alertDetailRows.length" class="alert-detail-fields">
              <div v-for="row in alertDetailRows" :key="row.key" class="alert-detail-row">
                <span class="adr-label">{{ row.label }}</span>
                <span class="adr-value">{{ row.value }}</span>
              </div>
            </div>
            <div v-if="selectedAlert.description" class="alert-desc-text">{{ selectedAlert.description }}</div>
          </div>

          <div class="detail-description">
            <div class="detail-description-title">研判状态</div>
            <div class="keyinfo-controls">
              <div class="keyinfo-field">
                <span>研判结论</span>
                <el-select v-model="flowForm.conclusion" clearable size="small" :disabled="isClosed" @change="changeConclusion">
                  <el-option v-for="item in conclusionOptions" :key="item.value" :label="item.label" :value="item.value" />
                </el-select>
              </div>
              <div class="keyinfo-field">
                <span>状态</span>
                <el-select v-model="flowForm.status" size="small" :disabled="isClosed" @change="changeStatus">
                  <el-option v-for="item in statusOptions" :key="item.value" :label="item.label" :value="item.value" />
                </el-select>
              </div>
              <div class="keyinfo-field">
                <span>当前处理人</span>
                <el-select
                  v-model="handlersModel"
                  multiple
                  filterable
                  allow-create
                  default-first-option
                  size="small"
                  :disabled="isClosed || !hasPerm('alert.assign')"
                  placeholder="选择或添加处理人（可多个）"
                  @change="saveHandlers"
                >
                  <el-option v-for="name in analystOptions" :key="name" :label="name" :value="name" />
                </el-select>
              </div>
            </div>
          </div>

          <div class="detail-grid2">
            <div class="detail-description">
            <div class="detail-description-title research-title-row">
              <span>研判信息</span>
              <el-button v-if="!isClosed" size="small" text @click="toggleResearchCollapsed">{{ researchCollapsed ? '展开填写' : '收起' }}</el-button>
            </div>
            <div v-if="isClosed" class="closed-lock-hint">
              告警已完成并锁定。重开请用上方按钮：「<strong>重新研判</strong>」(补充上下文后直接改判·留人续办) ·「<strong>指派</strong>」(换人续办) ·「<strong>驳回重判</strong>」(打回·清空重启)。
            </div>
            <div v-if="responderHint" class="responder-hint">
              <span>已转入应急响应处置。当前处理人：<strong>{{ (selectedAlert.handlers || []).join('、') || '无' }}</strong>。真实攻击 / 安全事件通常需多团队协同，可拆分处置子任务分派各团队。</span>
              <div class="responder-hint-actions">
                <el-button v-if="canCoordinateSubtasks" size="small" type="warning" @click="openSubtaskTab">拆分处置子任务</el-button>
                <el-button v-if="canCoordinateSubtasks" size="small" @click="openResponderAssign">指派处置人</el-button>
                <el-button size="small" text @click="responderHint = false">暂不</el-button>
              </div>
            </div>
            <div v-if="!isClosed && researchCollapsed" class="research-mini research-mini-row">
              <span v-for="k in ['key_evidence', 'handling_suggestion']" :key="k" class="research-mini-item" :class="researchItemState(k)">{{ RESEARCH_LABELS[k] }}</span>
            </div>
            <div v-show="!researchCollapsed && !isClosed" class="closure-summary keyinfo-display">
              <div class="closure-item" :class="{ 'is-stale': staleResearch.key_evidence, 'is-missing': researchItemState('key_evidence') === 'todo' }">
                <span>研判依据
                  <em v-if="staleResearch.key_evidence" class="stale-flag">待复核</em>
                  <em v-else-if="(selectedAlert?.key_evidence || '').trim()" class="recorded-flag">已记录 · 见研判记录</em>
                  <em v-else class="need-flag">完成前必填</em>
                </span>
                <div v-if="staleResearch.key_evidence" class="stale-actions">
                  <em class="stale-note">结论已变更，请核对原研判依据</em>
                  <el-button size="small" text @click="keepResearch('key_evidence')">沿用</el-button>
                  <el-button size="small" text type="warning" @click="clearResearch('key_evidence')">清空重填</el-button>
                </div>
                <el-input
                  v-model="researchInputs.key_evidence"
                  :disabled="researchReadonly"
                  type="textarea"
                  :autosize="{ minRows: 2, maxRows: 8 }"
                  placeholder="研判依据（含举证）：用文字说明为何得出该结论——攻击链/战术、IOC/Hash、日志要点、外部情报等；可粘贴/拖拽截图作为佐证，点“提交研判信息”加入研判记录"
                  @paste="e => handleResearchPaste(e, 'key_evidence')"
                  @dragover.prevent
                  @drop.prevent="e => handleResearchDrop(e, 'key_evidence')"
                />
                <div v-if="researchPending.key_evidence.length" class="research-staged">
                  <div v-for="(img, i) in researchPending.key_evidence" :key="i" class="research-staged-item">
                    <img :src="img.preview" alt="待加入截图" />
                    <button class="staged-remove" title="移除" @click="removeStaged('key_evidence', i)">×</button>
                  </div>
                </div>
              </div>
              <div class="closure-item" :class="{ 'is-missing': researchItemState('handling_suggestion') === 'todo' }">
                <span>处置建议
                  <em v-if="(selectedAlert?.handling_suggestion || '').trim()" class="recorded-flag">已记录 · 见研判记录</em>
                  <em v-else class="need-flag">完成前必填</em>
                </span>
                <el-input
                  v-model="researchInputs.handling_suggestion"
                  :disabled="researchReadonly"
                  type="textarea"
                  :autosize="{ minRows: 2, maxRows: 8 }"
                  placeholder="记录处置建议：封禁、隔离、查杀、加白、规则优化等；可粘贴/拖拽截图暂存，点“确认”与文字一并加入研判记录"
                  @paste="e => handleResearchPaste(e, 'handling_suggestion')"
                  @dragover.prevent
                  @drop.prevent="e => handleResearchDrop(e, 'handling_suggestion')"
                />
                <div v-if="researchPending.handling_suggestion.length" class="research-staged">
                  <div v-for="(img, i) in researchPending.handling_suggestion" :key="i" class="research-staged-item">
                    <img :src="img.preview" alt="待加入截图" />
                    <button class="staged-remove" title="移除" @click="removeStaged('handling_suggestion', i)">×</button>
                  </div>
                </div>
              </div>
              <div class="research-submit-bar">
                <el-button size="small" type="primary" :disabled="!researchDirty || researchReadonly || !hasPerm('alert.conclude')" @click="submitResearch">提交研判信息</el-button>
              </div>
            </div>
          </div>

          <div class="detail-description subtask-card">
            <div class="research-fill-head">
              <span class="research-fill-title">处置子任务</span>
              <span v-if="(selectedAlert.subtasks || []).length" class="tab-count">{{ (selectedAlert.subtasks || []).length }}</span>
              <span class="subtask-optional">可选</span>
              <el-button v-if="!subtaskAdding && !isClosed && canCoordinateSubtasks" size="small" type="primary" plain @click="openSubtaskAdd">
                <el-icon><Plus /></el-icon>添加处置子任务
              </el-button>
            </div>
            <div v-if="subtaskAdding && !isClosed" class="subtask-add">
              <el-input v-model="subtaskForm.title" size="small" placeholder="处置项，如：隔离 host-01 / 封禁 1.2.3.4 / 重置账号" @keyup.enter="submitSubtask" />
              <el-input v-model="subtaskForm.team" size="small" class="subtask-narrow" placeholder="团队/部门" />
              <el-input v-model="subtaskForm.assignee" size="small" class="subtask-narrow" placeholder="负责人" />
              <el-button size="small" type="primary" :disabled="!subtaskForm.title.trim()" @click="submitSubtask">添加</el-button>
              <el-button size="small" @click="cancelSubtaskAdd">取消</el-button>
            </div>
            <div class="subtask-list">
              <div v-for="st in (selectedAlert.subtasks || [])" :key="st.id" class="subtask-item" :class="'st-' + st.status">
                <div class="subtask-main">
                  <span class="subtask-title" :class="{ done: st.status === 'done' }">{{ st.title }}</span>
                  <span v-if="st.team" class="subtask-tag team">{{ st.team }}</span>
                  <span v-if="st.assignee" class="subtask-tag person">{{ st.assignee }}</span>
                </div>
                <div class="subtask-ops">
                  <el-select v-model="st.status" size="small" class="subtask-status" :disabled="!canExecuteSubtask(st)" @change="changeSubtaskStatus(st)">
                    <el-option v-for="s in subtaskStatusOptions" :key="s.value" :label="s.label" :value="s.value" />
                  </el-select>
                  <button v-if="canCoordinateSubtasks" class="subtask-del" title="删除" @click="removeSubtask(st)"><el-icon><Delete /></el-icon></button>
                </div>
              </div>
              <div v-if="!(selectedAlert.subtasks || []).length" class="empty-state">暂无处置子任务。需其他团队协同处置（如封禁 IP、隔离主机）时在此拆分分派；误报等无需处置可留空。</div>
            </div>
              </div>
          </div>

          <div class="detail-description detail-record-full">
            <div class="detail-description-title">研判记录</div>
            <div class="timeline">
              <template v-for="grp in researchRounds" :key="'rn' + grp.round">
                <div v-if="researchRounds.length > 1" class="round-divider">第 {{ grp.round }} 轮研判</div>
                <div v-for="note in grp.items" :key="note.id" class="timeline-item">
                  <div class="timeline-time">{{ formatTime(note.created_at) }} · {{ note.author || '-' }}</div>
                  <div v-if="noteText(note)" class="timeline-content">{{ noteText(note) }}</div>
                  <div v-if="noteImages(note).length" class="timeline-shots">
                    <el-image
                      v-for="(u, i) in noteImages(note)"
                      :key="i"
                      :src="u"
                      :preview-src-list="noteImages(note)"
                      :initial-index="i"
                      fit="cover"
                      hide-on-click-modal
                      preview-teleported
                      class="timeline-shot"
                    />
                  </div>
                </div>
              </template>
              <div v-if="!researchNotes.length" class="empty-state">暂无研判记录</div>
            </div>
          </div>

          <el-tabs v-model="activeTab" class="detail-tabs">
            <el-tab-pane label="流转记录" name="assignments">
              <div class="timeline">
                <template v-for="grp in flowRounds" :key="'fn' + grp.round">
                  <div v-if="flowRounds.length > 1" class="round-divider">第 {{ grp.round }} 轮研判</div>
                  <div v-for="note in grp.items" :key="note.id" class="timeline-item">
                    <div class="timeline-time">{{ formatTime(note.created_at) }} · {{ note.author || '-' }}</div>
                    <div class="timeline-content">{{ note.content }}</div>
                  </div>
                </template>
                <div v-if="!flowNotes.length" class="empty-state">暂无流转记录</div>
              </div>
            </el-tab-pane>

            <el-tab-pane v-if="hasPerm('audit.view')" label="审计记录" name="audit">
              <div class="timeline">
                <div v-for="item in deleteAudits" :key="item.id" class="timeline-item">
                  <div class="timeline-time">{{ formatTime(item.created_at) }} · {{ item.actor || '-' }} · {{ auditActionLabel(item.action) }}</div>
                  <div class="timeline-content">{{ auditSummary(item) }}</div>
                </div>
                <div v-if="!deleteAudits.length" class="empty-state">暂无删除记录</div>
              </div>
            </el-tab-pane>

          </el-tabs>
        </div>
      </el-dialog>
    </div>

    <el-dialog v-model="batchNoteDialogVisible" title="批量备注" width="520px" :close-on-click-modal="false">
      <el-input
        v-model="batchNoteDraft"
        type="textarea"
        :rows="6"
        maxlength="20000"
        show-word-limit
        placeholder="记录统一处理说明"
      />
      <template #footer>
        <el-button @click="batchNoteDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="batchLoading" :disabled="!batchNoteDraft.trim()" @click="submitBatchNote">
          确认
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="createDialogVisible"
      width="90vw"
      :fullscreen="createDialogFullscreen"
      :close-on-click-modal="false"
      @closed="cleanupCreateAssets"
    >
      <template #header>
        <div class="dialog-header">
          <span class="dialog-header-title">{{ editingAlertId ? '编辑告警' : '新建研判告警' }}</span>
          <el-button size="small" text @click="createDialogFullscreen = !createDialogFullscreen">
            {{ createDialogFullscreen ? '退出全屏' : '全屏' }}
          </el-button>
        </div>
      </template>
      <el-form label-position="top" class="create-form">
        <div class="optional-field-panel">
          <el-dropdown
            trigger="click"
            :disabled="!availableOptionalFields.length"
            @command="addOptionalField"
          >
            <el-button size="small" plain>
              <el-icon><Plus /></el-icon>{{ availableOptionalFields.length ? '添加字段' : '已全部添加' }}
            </el-button>
            <template #dropdown>
              <el-dropdown-menu class="optional-field-menu">
                <el-dropdown-item
                  v-for="item in availableOptionalFields"
                  :key="item.key"
                  :command="item.key"
                >
                  <span>{{ item.label }}</span>
                  <small>{{ item.group }}</small>
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
          <span v-if="!visibleOptionalFields.length" class="no-optional-hint">暂未添加补充字段</span>
        </div>
        <div class="form-grid">
          <el-form-item label="安全设备" required>
            <el-select v-model="createForm.source_category" clearable placeholder="请选择安全设备类型">
              <el-option v-for="item in templateOptions" :key="item.value" :label="item.label" :value="item.value" />
            </el-select>
          </el-form-item>
          <el-form-item label="告警名称" required>
            <el-input
              v-model="createForm.title"
              maxlength="120"
              show-word-limit
              placeholder="例如：可疑 PowerShell 执行行为"
            />
          </el-form-item>
          <el-form-item label="攻击 IP" required>
            <el-input v-model="createForm.source_ip" placeholder="攻击来源 IP" />
          </el-form-item>
          <el-form-item label="被攻击 IP" required>
            <el-input v-model="createForm.destination_ip" placeholder="受攻击资产 IP" />
          </el-form-item>
          <el-form-item label="上报人" required>
            <el-input v-model="createForm.reporter" placeholder="告警提交或上报人员" />
          </el-form-item>
          <el-form-item label="上报时间">
            <el-input :model-value="reportTime ? formatTime(reportTime) : '创建时自动生成'" disabled />
          </el-form-item>

          <el-form-item
            v-for="item in visibleOptionalFields"
            :key="item.key"
            required
            :class="{ 'span-2': item.wide }"
          >
            <template #label>
              <div class="optional-field-label">
                <span>{{ item.label }}</span>
                <el-tooltip content="移除此字段" placement="top">
                  <button
                    type="button"
                    class="remove-field-button"
                    :aria-label="`移除${item.label}`"
                    @click="removeOptionalField(item.key)"
                  >
                    <el-icon><Close /></el-icon>
                  </button>
                </el-tooltip>
              </div>
            </template>
            <el-date-picker
              v-if="item.type === 'datetime'"
              v-model="createForm[item.key]"
              type="datetime"
              value-format="YYYY-MM-DDTHH:mm:ssZ"
            />
            <el-select v-else-if="item.type === 'severity'" v-model="createForm.severity">
              <el-option v-for="option in severityOptions" :key="option.value" :label="option.label" :value="option.value" />
            </el-select>
            <el-input
              v-else-if="item.type === 'textarea'"
              v-model="createForm[item.key]"
              type="textarea"
              :rows="5"
              :placeholder="item.placeholder"
            />
            <el-input v-else v-model="createForm[item.key]" :placeholder="item.placeholder || '选填'" />
          </el-form-item>

          <el-form-item label="告警详情" required class="span-2">
            <el-input
              v-model="createForm.description"
              type="textarea"
              :rows="5"
              placeholder="粘贴或输入安全设备中的告警详情；也可在此直接 Ctrl+V 粘贴截图"
              @paste.capture="handleDetailPaste"
            />
          </el-form-item>

          <div class="screenshot-section span-2">
            <div class="screenshot-section-title"><span v-if="!editingAlertId" class="req-star">*</span>告警截图{{ editingAlertId ? '（可追加截图 / 日志）' : '（至少上传一张）' }}</div>
            <div
              v-for="(slot, index) in createScreenshotSlots"
              :key="slot.id"
              class="screenshot-field"
            >
              <div class="screenshot-field-header">
                <span>告警截图 {{ index + 1 }}</span>
                <el-tooltip content="移除此截图" placement="top">
                  <button
                    type="button"
                    class="remove-field-button"
                    :aria-label="`移除告警截图${index + 1}`"
                    @click="removeScreenshotSlot(slot.id)"
                  >
                    <el-icon><Close /></el-icon>
                  </button>
                </el-tooltip>
              </div>
              <div
                class="screenshot-paste-zone"
                tabindex="0"
                @click="openScreenshotPicker"
                @paste="handleScreenshotPaste($event, slot.id)"
                @dragover.prevent
                @drop.prevent="handleScreenshotDrop($event, slot.id)"
              >
                <input
                  hidden
                  type="file"
                  accept="image/*"
                  @change="handleScreenshotPick($event, slot.id)"
                />
                <img v-if="slot.previewUrl" :src="slot.previewUrl" :alt="slot.file?.name || `告警截图 ${index + 1}`" />
                <template v-else>
                  <el-icon :size="24"><Upload /></el-icon>
                  <span>点击选择、拖拽图片到此，或聚焦后 Ctrl+V 粘贴</span>
                </template>
              </div>
            </div>
            <el-button size="small" plain @click="addScreenshotSlot">
              <el-icon><Plus /></el-icon>添加截图
            </el-button>
          </div>

          <el-form-item label="其他附件" class="span-2">
            <input ref="createAttachmentInputRef" hidden type="file" multiple @change="handleCreateAttachmentPick" />
            <div class="create-attachment-field">
              <div
                class="create-attachments"
                tabindex="0"
                @click="createAttachmentInputRef?.click()"
                @dragover.prevent
                @drop.prevent="handleCreateAttachmentDrop"
                @paste="handleCreateAttachmentPaste"
              >
                <el-icon><Upload /></el-icon>
                <span>{{ createFiles.length ? `继续添加附件（当前 ${createFiles.length} 个）` : '点击选择、拖拽文件到此，或聚焦后 Ctrl+V 粘贴（PCAP/PCAPNG、日志、ZIP/RAR 压缩包、图片等）' }}</span>
              </div>
              <div v-if="createFiles.length" class="create-file-list">
                <div
                  v-for="(file, index) in createFiles"
                  :key="`${file.name}-${file.size}-${file.lastModified}-${index}`"
                  class="create-file-item"
                >
                  <el-icon><Document /></el-icon>
                  <span class="create-file-name" :title="file.name">{{ file.name }}</span>
                  <small>{{ formatFileSize(file.size) }}</small>
                  <el-tooltip content="移除此附件" placement="top">
                    <button
                      type="button"
                      class="remove-field-button create-file-remove"
                      :aria-label="`移除附件 ${file.name}`"
                      @click="removeCreateFile(index)"
                    >
                      <el-icon><Delete /></el-icon>
                    </button>
                  </el-tooltip>
                </div>
              </div>
            </div>
          </el-form-item>
          <div class="form-actions span-2">
            <el-button @click="createDialogVisible = false">取消</el-button>
            <template v-if="editingAlertId">
              <el-button :type="editingStatus === 'new' ? 'default' : 'primary'" :loading="submitting" @click="submitCreate(editingStatus === 'new' ? 'draft' : 'edit')">
                {{ editingStatus === 'new' ? '保存告警' : '保存' }}
              </el-button>
              <el-button v-if="editingStatus === 'new'" type="primary" :loading="submitting" @click="submitCreate('submit')">
                创建告警
              </el-button>
            </template>
            <template v-else>
              <el-button :loading="submitting" @click="submitCreate('draft')">
                保存告警
              </el-button>
              <el-button type="primary" :loading="submitting" @click="submitCreate('submit')">
                创建告警
              </el-button>
            </template>
          </div>
        </div>
      </el-form>
    </el-dialog>

    <el-dialog
      v-model="assignDialogVisible"
      title="指派处理人"
      width="520px"
      :close-on-click-modal="false"
    >
      <div class="assign-target" v-if="assignTarget">
        <span class="assign-target-label">告警</span>
        <strong :title="assignTarget.title">{{ assignTarget.title }}</strong>
      </div>
      <div class="assign-block">
        <span class="assign-block-label">当前处理人</span>
        <div class="assign-tags">
          <el-tag
            v-for="h in (assignTarget?.handlers || [])"
            :key="h"
            closable
            type="success"
            @close="removeHandlerFn(h)"
          >{{ h }}</el-tag>
          <span v-if="!assignTarget?.handlers?.length" class="empty-inline">暂无处理人</span>
        </div>
      </div>
      <div class="assign-add">
        <el-select
          v-model="assignNewHandler"
          multiple
          filterable
          allow-create
          default-first-option
          clearable
          size="small"
          placeholder="选择或输入处理人姓名（可多选）"
        >
          <el-option v-for="name in analystOptions" :key="name" :label="name" :value="name" />
        </el-select>
        <el-button
          type="primary"
          size="small"
          :loading="assignSubmitting"
          :disabled="!assignNewHandler.length"
          @click="addHandler"
        >添加处理人</el-button>
      </div>
      <template #footer>
        <el-button @click="assignDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="rejectDialogVisible" title="驳回重判" width="480px">
      <p class="reject-hint">
        将<strong>清空重启</strong>本告警：回退至「待分配」，清空 研判结论 / 当前处理人 / 研判依据·举证信息·处置建议，仅保留流转记录，轮次 +1。
      </p>
      <el-input
        v-model="rejectReason"
        type="textarea"
        :rows="3"
        placeholder="驳回原因（选填）：说明研判结论为何被否、需要补充哪些证据或研判"
      />
      <template #footer>
        <el-button @click="rejectDialogVisible = false">取消</el-button>
        <el-button type="warning" @click="submitReject">确认驳回</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="reopenDialogVisible" title="重新研判" width="480px">
      <p class="reopen-hint">
        补充上下文后<strong>直接改判并重开</strong>：保留当前处理人，轮次 +1，进入研判中（事件类结论自动转应急响应中）。原研判内容将归档到研判记录，处置建议清空、研判依据·举证信息标记待复核。
      </p>
      <div class="reopen-field">
        <span>新的研判结论</span>
        <el-select v-model="reopenForm.conclusion" size="small" placeholder="选择改判后的结论">
          <el-option v-for="item in conclusionOptions" :key="item.value" :label="item.label" :value="item.value" />
        </el-select>
      </div>
      <el-input
        v-model="reopenForm.reason"
        type="textarea"
        :rows="3"
        placeholder="重研原因（选填）：补充了哪些上下文、为何改判"
      />
      <template #footer>
        <el-button @click="reopenDialogVisible = false">取消</el-button>
        <el-button type="danger" :disabled="!reopenForm.conclusion" @click="submitReopen">确认重研</el-button>
      </template>
    </el-dialog>

  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowLeft, ArrowRight, Close, Delete, Document, Download, Plus, Refresh, Search, Upload } from '@element-plus/icons-vue'
import {
  addIncidentEntity,
  addIncidentNote,
  batchIncidentAlerts,
  createIncidentAlert,
  deleteIncidentAlert,
  deleteIncidentAttachment,
  downloadIncidentAttachment,
  deleteIncidentEntity,
  exportIncidentAlertMarkdown,
  exportIncidentOperationsCsv,
  getIncidentCorrelation,
  getIncidentAlert,
  getIncidentOperations,
  getIncidentStats,
  getIncidentTemplates,
  getAuthDirectory,
  listIncidentAlerts,
  setIncidentAlertConclusion,
  setIncidentAlertStatus,
  setIncidentHandlers,
  rejectIncidentAlert,
  reopenIncidentAlert,
  listIncidentSubtasks,
  addIncidentSubtask,
  updateIncidentSubtask,
  deleteIncidentSubtask,
  updateIncidentAlert,
  uploadIncidentAttachment,
  uploadIncidentAttachments
} from '../api'
import { auth } from '../store/auth'
import { validateIncidentFiles } from '../utils/incidentFileValidation'
import { clearSessionResume, peekSessionResume } from '../utils/sessionResume'
import { clearSessionDraft, peekSessionDraft, saveSessionDraft } from '../utils/sessionDraft'
import { shouldIgnoreRowClick } from '../utils/tableInteraction'

// 按权限显隐/禁用操作入口（后端仍是强制校验，前端仅做体验）
const hasPerm = (perm) => auth.hasPerm(perm)
// 真实账号目录（指派选人候选）
const directoryUsers = ref([])

const statusOptions = [
  { value: 'new', label: '创建中' },
  { value: 'pending', label: '待分配' },
  { value: 'investigating', label: '研判中' },
  { value: 'responding', label: '应急响应中' },
  { value: 'closed', label: '已完成' }
]
const severityOptions = [
  { value: 'critical', label: '严重' },
  { value: 'high', label: '高危' },
  { value: 'medium', label: '中危' },
  { value: 'low', label: '低危' },
  { value: 'info', label: '信息' }
]
const conclusionOptions = [
  { value: 'false_positive', label: '告警误报' },
  { value: 'business', label: '正常业务' },
  { value: 'true_positive', label: '真实攻击' },
  { value: 'incident', label: '安全事件' },
  { value: 'unknown', label: '无法确认' }
]
const queueOptions = [
  { value: 'all', label: '全部' },
  { value: 'active', label: '处理中' },
  { value: 'my', label: '我的待办' },
  { value: 'unassigned', label: '未分派' },
  { value: 'closed', label: '已完成' }
]
const currentUser = auth.username || 'operator'

const loading = ref(false)
const submitting = ref(false)
const batchLoading = ref(false)
const correlationLoading = ref(false)
const alerts = ref([])
const selectedRows = ref([])
const selectedAlert = ref(null)
const detailDialogVisible = ref(false)
const stats = ref({})
const operations = ref({})
const operationDays = ref(7)
const activeTab = ref('assignments')
const filters = ref({ keyword: '', status: '', severity: '', source_category: '', reporter: '', owner: '', queue: 'all', current_user: currentUser })
const flowForm = ref({ status: '', conclusion: '' })
const editForm = ref({ reporter: '' })
const researchInputs = ref({ key_evidence: '', handling_suggestion: '' })
const RESEARCH_LABELS = { key_evidence: '研判依据', handling_suggestion: '处置建议' }
const EVENT_CONCLUSIONS = ['true_positive', 'incident']
const staleResearch = ref({ key_evidence: false, handling_suggestion: false })
const responderHint = ref(false)
const statusPulse = ref(false)
// 研判三框待加入的暂存截图（点“确认”时随文字一并落库）：{ file, preview }
const researchPending = ref({ key_evidence: [], handling_suggestion: [] })
const researchSubmission = ref({ key_evidence: null, handling_suggestion: null })
// 研判三框折叠（默认收起，正文看研判记录；折叠状态记忆到 localStorage）
const researchCollapsed = ref(localStorage.getItem('research_collapsed') !== '0')
// 应急响应处置子任务（轻量）
const subtaskForm = ref({ title: '', team: '', assignee: '' })
const subtaskAdding = ref(false)
const subtaskStatusOptions = [
  { value: 'todo', label: '待处理' },
  { value: 'doing', label: '处理中' },
  { value: 'done', label: '已完成' }
]
const batchForm = ref({ owner: '', severity: '', status: '' })
const batchNoteDialogVisible = ref(false)
const batchNoteDraft = ref('')
const entityForm = ref({ entity_type: 'ip', value: '' })
const attachmentInputRef = ref(null)
const createAttachmentInputRef = ref(null)
const isDragging = ref(false)
const isListDragging = ref(false)
const listDragDepth = ref(0)
const rejectDialogVisible = ref(false)
const rejectReason = ref('')
const reopenDialogVisible = ref(false)
const reopenForm = ref({ conclusion: '', reason: '' })
const assignDialogVisible = ref(false)
const assignTarget = ref(null)
const assignNewHandler = ref([])
const assignSubmitting = ref(false)
const handlersModel = ref([])
const createFiles = ref([])
const createScreenshotSlots = ref([])
const pendingEvidenceUploads = ref([])
const pendingQuickCreates = ref([])
const selectedOptionalFieldKeys = ref([])
const createDialogVisible = ref(false)
const editingAlertId = ref(null)
const editingStatus = ref('')
const editOriginal = ref(null)
const reportTime = ref('')
const createDialogFullscreen = ref(false)
const createForm = ref(newCreateForm())
const rawViewMode = ref('formatted')
const templates = ref({
  other: {
    label: '其他 / 通用',
    description: '不限定设备类型，仅填写实际存在的字段。',
    fields: []
  }
})

const resumableFilterKeys = [
  'keyword', 'status', 'severity', 'source_category', 'reporter', 'owner', 'queue'
]

function captureSessionResume(event) {
  const setViewState = event?.detail?.setViewState
  if (typeof setViewState !== 'function') return

  const savedFilters = {}
  for (const key of resumableFilterKeys) {
    savedFilters[key] = String(filters.value[key] || '').slice(0, 500)
  }

  setViewState.call(event.detail, {
    kind: 'incident',
    filters: savedFilters,
    operationDays: operationDays.value,
    activeTab: activeTab.value,
    selectedAlertId: selectedAlert.value?.id || '',
    detailOpen: detailDialogVisible.value,
    researchCollapsed: researchCollapsed.value,
    selectedAlertIds: selectedAlertIds.value,
    batchForm: { ...batchForm.value },
    batchNoteOpen: batchNoteDialogVisible.value,
    batchNoteDraft: String(batchNoteDraft.value || '').slice(0, 20000),
    researchInputs: {
      key_evidence: String(researchInputs.value.key_evidence || '').slice(0, 20000),
      handling_suggestion: String(researchInputs.value.handling_suggestion || '').slice(0, 20000),
    },
    researchSubmission: {
      key_evidence: researchSubmission.value.key_evidence,
      handling_suggestion: researchSubmission.value.handling_suggestion,
    },
    subtaskAdding: subtaskAdding.value,
    subtaskForm: { ...subtaskForm.value },
    assignOpen: assignDialogVisible.value,
    assignTargetId: assignTarget.value?.id || '',
    assignNewHandler: [...assignNewHandler.value],
    rejectOpen: rejectDialogVisible.value,
    rejectReason: String(rejectReason.value || '').slice(0, 20000),
    reopenOpen: reopenDialogVisible.value,
    reopenForm: { ...reopenForm.value },
    createOpen: createDialogVisible.value,
    createFullscreen: createDialogFullscreen.value,
    editingAlertId: editingAlertId.value || '',
    editingStatus: editingStatus.value || '',
    reportTime: reportTime.value || '',
    selectedOptionalFieldKeys: [...selectedOptionalFieldKeys.value],
    createForm: { ...createForm.value },
    createScreenshotSlotIds: createScreenshotSlots.value.map(slot => slot.id),
    queueScrollTop: opsScrollEl?.scrollTop || 0,
    detailScrollTop: detailScrollEl?.scrollTop || 0,
  })

  const addPersistence = event?.detail?.addPersistence
  if (typeof addPersistence === 'function') {
    addPersistence.call(event.detail, saveSessionDraft(auth.username, {
      kind: 'incident',
      createFiles: [...createFiles.value],
      createScreenshots: createScreenshotSlots.value.map(slot => ({
        id: slot.id,
        file: slot.file || null,
      })),
      researchPending: Object.fromEntries(
        Object.entries(researchPending.value).map(([key, items]) => [
          key,
          items.map(item => item.file).filter(Boolean),
        ])
      ),
      pendingEvidenceUploads: [...pendingEvidenceUploads.value],
      pendingQuickCreates: pendingQuickCreates.value.map(item => ({
        file: item.file,
        alertId: item.alertId || '',
      })),
    }))
  }
}

async function restoreSessionResume() {
  const resume = peekSessionResume(auth.username)
  const state = resume?.viewState?.incident
    || (resume?.viewState?.kind === 'incident' ? resume.viewState : null)
  if (!state || state.kind !== 'incident') return false
  const fileState = await peekSessionDraft(auth.username)

  if (state.filters && typeof state.filters === 'object') {
    for (const key of resumableFilterKeys) {
      if (typeof state.filters[key] === 'string') filters.value[key] = state.filters[key]
    }
  }
  filters.value.current_user = currentUser

  const restoredDays = Number(state.operationDays)
  if (Number.isFinite(restoredDays) && restoredDays >= 1 && restoredDays <= 365) {
    operationDays.value = restoredDays
  }
  if (['assignments', 'audit'].includes(state.activeTab)) activeTab.value = state.activeTab
  if (typeof state.researchCollapsed === 'boolean') {
    researchCollapsed.value = state.researchCollapsed
  }
  if (state.batchForm && typeof state.batchForm === 'object') {
    batchForm.value = {
      owner: String(state.batchForm.owner || ''),
      severity: String(state.batchForm.severity || ''),
      status: String(state.batchForm.status || ''),
    }
  }
  batchNoteDraft.value = String(state.batchNoteDraft || '').slice(0, 20000)
  batchNoteDialogVisible.value = !!state.batchNoteOpen

  await refreshAll()

  if (state.detailOpen && typeof state.selectedAlertId === 'string' && state.selectedAlertId) {
    await selectAlert({ id: state.selectedAlertId })
    if (state.researchInputs && typeof state.researchInputs === 'object') {
      researchInputs.value = {
        key_evidence: String(state.researchInputs.key_evidence || '').slice(0, 20000),
        handling_suggestion: String(state.researchInputs.handling_suggestion || '').slice(0, 20000),
      }
    }
    if (state.researchSubmission && typeof state.researchSubmission === 'object') {
      for (const key of Object.keys(researchSubmission.value)) {
        const item = state.researchSubmission[key]
        researchSubmission.value[key] = item && typeof item === 'object'
          ? {
              text: String(item.text || '').slice(0, 20000),
              urls: Array.isArray(item.urls) ? item.urls.map(String) : [],
            }
          : null
      }
    }
    subtaskAdding.value = !!state.subtaskAdding
    if (state.subtaskForm && typeof state.subtaskForm === 'object') {
      subtaskForm.value = {
        title: String(state.subtaskForm.title || '').slice(0, 1000),
        team: String(state.subtaskForm.team || '').slice(0, 500),
        assignee: String(state.subtaskForm.assignee || '').slice(0, 500),
      }
    }
    if (fileState?.researchPending) {
      for (const key of Object.keys(researchPending.value)) {
        const files = Array.isArray(fileState.researchPending[key])
          ? fileState.researchPending[key].filter(Boolean)
          : []
        researchPending.value[key] = files.map(file => ({
          file,
          preview: URL.createObjectURL(file),
        }))
      }
    }
  }

  if (state.createOpen) {
    cleanupCreateAssets()
    createForm.value = { ...newCreateForm(), ...(state.createForm || {}) }
    selectedOptionalFieldKeys.value = Array.isArray(state.selectedOptionalFieldKeys)
      ? state.selectedOptionalFieldKeys.filter(
          key => optionalFieldDefinitions.some(item => item.key === key)
        )
      : []
    editingAlertId.value = String(state.editingAlertId || '') || null
    editingStatus.value = String(state.editingStatus || '')
    reportTime.value = String(state.reportTime || '')
    createDialogFullscreen.value = !!state.createFullscreen

    if (editingAlertId.value) {
      try {
        const original = await getIncidentAlert(editingAlertId.value)
        if (original.success) editOriginal.value = original.data
      } catch (_) {}
    }

    const storedScreenshots = Array.isArray(fileState?.createScreenshots)
      ? fileState.createScreenshots
      : []
    const slotIds = Array.isArray(state.createScreenshotSlotIds)
      ? state.createScreenshotSlotIds
      : storedScreenshots.map(item => item.id)
    createScreenshotSlots.value = slotIds.map((id) => {
      const file = storedScreenshots.find(item => item.id === id)?.file || null
      return { id, file, previewUrl: file ? URL.createObjectURL(file) : '' }
    })
    if (!createScreenshotSlots.value.length) createScreenshotSlots.value = [newScreenshotSlot()]
    createFiles.value = Array.isArray(fileState?.createFiles)
      ? fileState.createFiles.filter(Boolean)
      : []
    createDialogVisible.value = true
  }

  if (state.assignOpen && state.assignTargetId) {
    try {
      const target = selectedAlert.value?.id === state.assignTargetId
        ? selectedAlert.value
        : (await getIncidentAlert(state.assignTargetId)).data
      if (target) {
        assignTarget.value = target
        assignNewHandler.value = Array.isArray(state.assignNewHandler)
          ? state.assignNewHandler.map(String)
          : []
        assignDialogVisible.value = true
      }
    } catch (_) {}
  }
  rejectReason.value = String(state.rejectReason || '').slice(0, 20000)
  rejectDialogVisible.value = !!state.rejectOpen && !!selectedAlert.value
  if (state.reopenForm && typeof state.reopenForm === 'object') {
    reopenForm.value = {
      conclusion: String(state.reopenForm.conclusion || ''),
      reason: String(state.reopenForm.reason || '').slice(0, 20000),
    }
  }
  reopenDialogVisible.value = !!state.reopenOpen && !!selectedAlert.value

  await nextTick()
  if (Array.isArray(state.selectedAlertIds) && alertTableRef.value) {
    const wanted = new Set(state.selectedAlertIds.map(String))
    for (const row of alerts.value) {
      if (wanted.has(String(row.id))) alertTableRef.value.toggleRowSelection(row, true)
    }
  }
  bindQueueScroll()
  if (opsScrollEl && Number.isFinite(Number(state.queueScrollTop))) {
    opsScrollEl.scrollTop = Math.max(0, Number(state.queueScrollTop))
  }
  if (state.detailOpen) {
    bindDetailScroll()
    if (detailScrollEl && Number.isFinite(Number(state.detailScrollTop))) {
      detailScrollEl.scrollTop = Math.max(0, Number(state.detailScrollTop))
    }
  }
  const retryEvidence = Array.isArray(fileState?.pendingEvidenceUploads)
    ? fileState.pendingEvidenceUploads.filter(Boolean)
    : []
  const retryQuickCreates = Array.isArray(fileState?.pendingQuickCreates)
    ? fileState.pendingQuickCreates.filter(item => item?.file)
    : []
  const hasResumedResearch = Object.values(researchSubmission.value).some(Boolean)
  await clearSessionDraft(auth.username)
  clearSessionResume()
  if (state.createOpen) {
    ElMessage.success('已恢复登录失效前的新建/编辑告警内容及待上传文件')
  } else if (state.detailOpen) {
    ElMessage.success('已恢复登录失效前的告警详情和未提交输入')
  }
  if (hasResumedResearch) {
    ElMessage.warning('部分研判截图已上传但记录尚未完成，请点击“提交研判信息”继续')
  }
  if (retryEvidence.length && selectedAlert.value) {
    ElMessage.info(`正在继续上传登录失效前选择的 ${retryEvidence.length} 个附件`)
    await uploadFiles(retryEvidence)
  }
  if (retryQuickCreates.length) {
    pendingQuickCreates.value = retryQuickCreates
    ElMessage.info(`正在继续处理登录失效前的 ${retryQuickCreates.length} 个截图建单任务`)
    await processQuickCreates()
  }
  return true
}

const fieldLabels = {
  source_ip: '源 IP',
  destination_ip: '目的 IP',
  source_port: '源端口',
  destination_port: '目的端口',
  hostname: '主机名',
  username: '用户名',
  domain: '域名',
  url: 'URL',
  file_hash: '文件 Hash',
  file_path: '文件路径',
  process_name: '进程名',
  command_line: '命令行',
  rule_name: '规则名称',
  rule_id: '规则 ID',
  protocol: '协议',
  http_method: 'HTTP 方法',
  http_status: '响应状态',
  user_agent: 'User-Agent',
  event_action: '检测动作'
}

const wideFields = new Set(['url', 'file_path', 'command_line', 'user_agent'])
// 从告警的归一化字段里取出非空项（含哈希/命令行/域名等），用于图片下方的「告警详情」可复制文本块
const alertDetailRows = computed(() => {
  const nf = selectedAlert.value?.normalized_fields || {}
  const rows = []
  // 已知字段按固定顺序
  for (const k of Object.keys(fieldLabels)) {
    if (String(nf[k] ?? '').trim()) rows.push({ key: k, label: fieldLabels[k], value: String(nf[k]) })
  }
  // 自定义字段（键名即标签）追加在后
  for (const k of Object.keys(nf)) {
    if (!(k in fieldLabels) && String(nf[k] ?? '').trim()) {
      rows.push({ key: k, label: k, value: String(nf[k]) })
    }
  }
  return rows
})
const deviceFieldKeys = Object.keys(fieldLabels)
const fixedFieldKeys = new Set(['source_ip', 'destination_ip'])
const optionalFieldDefinitions = [
  {
    key: 'source_system',
    label: '设备名称',
    group: '告警信息',
    placeholder: '具体设备或平台名称'
  },
  {
    key: 'alert_type',
    label: '告警类型',
    group: '告警信息',
    placeholder: '恶意进程 / 异常登录 / C2 通信'
  },
  ...deviceFieldKeys
    .filter(key => !fixedFieldKeys.has(key))
    .map(key => ({
      key,
      label: fieldLabels[key],
      group: '安全字段',
      wide: wideFields.has(key),
      placeholder: '选填'
    }))
]

const templateOptions = computed(() => Object.entries(templates.value).map(([value, item]) => ({
  value,
  label: item.label
})))

const visibleOptionalFields = computed(() => {
  const definitions = new Map(optionalFieldDefinitions.map(item => [item.key, item]))
  return selectedOptionalFieldKeys.value
    .map(key => definitions.get(key))
    .filter(Boolean)
})

const availableOptionalFields = computed(() => {
  const selected = new Set(selectedOptionalFieldKeys.value)
  return optionalFieldDefinitions.filter(item => !selected.has(item.key))
})

const selectedAlertIds = computed(() => selectedRows.value.map(item => item.id))

const populatedFields = computed(() => {
  const values = selectedAlert.value?.normalized_fields || {}
  const category = selectedAlert.value?.source_category || 'other'
  const preferred = templates.value[category]?.fields || []
  const orderedKeys = preferred.map(item => item.key)
  for (const key of deviceFieldKeys) {
    if (!orderedKeys.includes(key)) orderedKeys.push(key)
  }
  return orderedKeys
    .filter(key => values[key] !== undefined && values[key] !== null && String(values[key]).trim() !== '')
    .map(key => ({
      key,
      label: preferred.find(item => item.key === key)?.label || fieldLabels[key] || key,
      value: String(values[key]),
      wide: preferred.find(item => item.key === key)?.wide || wideFields.has(key)
    }))
})

const RESEARCH_SHOT_MARK = '研判记录截图'
const imageAttachments = computed(() =>
  (selectedAlert.value?.attachments || []).filter(att => att.file_type === 'image' && att.description !== RESEARCH_SHOT_MARK)
)
const otherAttachments = computed(() =>
  (selectedAlert.value?.attachments || []).filter(att => att.file_type !== 'image')
)
const imageUrls = computed(() => imageAttachments.value.map(att => att.url))

const NON_RESEARCH_NOTE_TYPES = ['system', 'status_change', 'assignment', 'edit']
function isFlowNote(n) {
  if (NON_RESEARCH_NOTE_TYPES.includes(n.note_type)) return true
  const c = n.content || ''
  return c.startsWith('自动导入') || c.startsWith('手动导入')
}
const researchNotes = computed(() =>
  (selectedAlert.value?.notes || []).filter(n => !isFlowNote(n))
)
const flowNotes = computed(() =>
  (selectedAlert.value?.notes || []).filter(n => isFlowNote(n))
)
const deleteAudits = computed(() =>
  (selectedAlert.value?.audit || []).filter(a => String(a.action || '').startsWith('delete'))
)

// 按研判轮次分组（笔记按创建时间倒序，轮次从高到低展示）
function groupByRound(notes) {
  const map = new Map()
  for (const n of notes) {
    const r = n.round || 1
    if (!map.has(r)) map.set(r, [])
    map.get(r).push(n)
  }
  return Array.from(map.entries())
    .sort((a, b) => b[0] - a[0])
    .map(([round, items]) => ({ round, items }))
}
const researchRounds = computed(() => groupByRound(researchNotes.value))
const flowRounds = computed(() => groupByRound(flowNotes.value))

// 研判记录里内联的截图：从笔记内容解析出图片 URL，并把纯文本与图片分开渲染
const RESEARCH_IMG_RE = /\/api\/incident\/files\/\S+?\.(?:png|jpe?g|gif|webp|bmp)/gi
function noteImages(note) {
  return String(note?.content || '').match(RESEARCH_IMG_RE) || []
}
function noteText(note) {
  return String(note?.content || '').replace(RESEARCH_IMG_RE, '').trim()
}
const isClosed = computed(() => selectedAlert.value?.status === 'closed')
const canCoordinateSubtasks = computed(() => hasPerm('subtask.manage'))
const canExecuteSubtask = (subtask) => canCoordinateSubtasks.value || (
  hasPerm('subtask.execute') && subtask?.assignee === currentUser
)
// 待分配 / 创建中：尚未进入研判，研判输入只读
const researchReadonly = computed(() => ['pending', 'new'].includes(selectedAlert.value?.status))

// 详情弹窗滚动时，顶部头自动缩小、只留上一条/下一条
const headerShrunk = ref(false)
let detailScrollEl = null
function onDetailScroll(e) { headerShrunk.value = (e.target?.scrollTop || 0) > 40 }
function bindDetailScroll() {
  const el = document.querySelector('.alert-detail-dialog .el-dialog__body')
  if (el) { detailScrollEl = el; el.addEventListener('scroll', onDetailScroll, { passive: true }) }
}
function unbindDetailScroll() {
  if (detailScrollEl) detailScrollEl.removeEventListener('scroll', onDetailScroll)
  detailScrollEl = null
  headerShrunk.value = false
}

// 处置子任务卡片按需显示：应急响应中 / 事件类结论 / 已有子任务；误报等无需处置时不显示（可选）
const showSubtasks = computed(() => {
  const s = selectedAlert.value
  if (!s) return false
  return s.status === 'responding' || EVENT_CONCLUSIONS.includes(s.conclusion) || (s.subtasks || []).length > 0
})

// 指派候选：优先真实账号目录（用户名即 handler 归属键），并入历史出现过的姓名兜底
const analystOptions = computed(() => {
  const set = new Set()
  for (const u of directoryUsers.value || []) set.add(u.username)
  for (const a of alerts.value || []) {
    if (a.owner) set.add(a.owner)
    if (a.created_by) set.add(a.created_by)
    for (const h of a.handlers || []) set.add(h)
  }
  if (selectedAlert.value?.owner) set.add(selectedAlert.value.owner)
  for (const h of selectedAlert.value?.handlers || []) set.add(h)
  return Array.from(set).sort()
})

const criticalCount = computed(() => {
  const bySeverity = stats.value.by_severity || {}
  return (bySeverity.critical || 0) + (bySeverity.high || 0)
})

const selectedAlertIndex = computed(() => (
  alerts.value.findIndex(item => item.id === selectedAlert.value?.id)
))

const selectedAlertPosition = computed(() => (
  selectedAlertIndex.value >= 0 ? selectedAlertIndex.value + 1 : '-'
))

const hasPreviousAlert = computed(() => selectedAlertIndex.value > 0)

const hasNextAlert = computed(() => (
  selectedAlertIndex.value >= 0 && selectedAlertIndex.value < alerts.value.length - 1
))

function newCreateForm() {
  return {
    title: '',
    source_category: '',
    reporter: '',
    source_system: '',
    alert_type: '',
    severity: '',
    source_ip: '',
    destination_ip: '',
    source_port: '',
    destination_port: '',
    hostname: '',
    username: '',
    domain: '',
    url: '',
    file_hash: '',
    file_path: '',
    process_name: '',
    rule_name: '',
    rule_id: '',
    command_line: '',
    protocol: '',
    http_method: '',
    http_status: '',
    user_agent: '',
    event_action: '',
    description: ''
  }
}

function severityClass(value) {
  return value || 'medium'
}

function statusTag(status) {
  if (status === 'closed') return 'info'
  if (status === 'confirmed') return 'success'
  if (status === 'responding') return 'danger'
  if (status === 'triaging' || status === 'investigating' || status === 'waiting_info' || status === 'need_info') return 'warning'
  if (status === 'assigned') return 'primary'
  return ''
}

function conclusionTag(conclusion) {
  if (conclusion === 'true_positive') return 'danger'   // 真实攻击 · 红
  if (conclusion === 'incident') return 'warning'       // 安全事件 · 橙
  if (conclusion === 'business') return 'success'       // 正常业务 · 绿
  if (conclusion === 'false_positive') return 'info'    // 告警误报 · 灰
  return ''                                             // 无法确认 · 默认
}

function correlationTagType(level) {
  if (level === 'strong') return 'danger'
  if (level === 'medium') return 'warning'
  if (level === 'weak') return 'info'
  return ''
}

function queueCount(queue) {
  if (queue === 'all') return stats.value.total || 0
  if (queue === 'active') return stats.value.pending || 0
  if (queue === 'unassigned') return stats.value.unassigned || 0
  if (queue === 'closed') return stats.value.by_status?.['已完成'] || 0
  return null
}

function switchQueue(queue) {
  filters.value.queue = queue
  loadAlerts()
}

function formatTime(value) {
  if (!value) return '-'
  try { return new Date(value).toLocaleString('zh-CN', { hour12: false }) } catch { return value }
}

function isJsonLike(str) {
  if (typeof str !== 'string') return false
  const s = str.trim()
  return (s.startsWith('{') && s.endsWith('}')) || (s.startsWith('[') && s.endsWith(']'))
}

function expandJsonStrings(obj) {
  if (obj === null || obj === undefined) return obj
  if (Array.isArray(obj)) return obj.map(item => expandJsonStrings(item))
  if (typeof obj === 'object') {
    const result = {}
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string' && isJsonLike(value)) {
        try { result[key] = JSON.parse(value) } catch { result[key] = value }
      } else if (typeof value === 'object' && value !== null) {
        result[key] = expandJsonStrings(value)
      } else {
        result[key] = value
      }
    }
    return result
  }
  return obj
}

function smartFormat(value) {
  if (value === null || value === undefined) return ''
  if (typeof value === 'object') {
    const expanded = expandJsonStrings(value)
    try { return JSON.stringify(expanded, null, 2) } catch { return String(value) }
  }
  if (typeof value === 'string') {
    if (isJsonLike(value)) {
      try { return JSON.stringify(JSON.parse(value), null, 2) } catch { return value }
    }
    return value
  }
  return String(value)
}

function formatJson(value) {
  try { return JSON.stringify(value || {}, null, 2) } catch { return String(value || '') }
}

function attachmentTypeLabel(fileType) {
  const labels = {
    pcap: 'PCAP',
    pcapng: 'PCAPNG',
    log: 'LOG',
    log_archive: '日志归档',
    archive: '压缩包'
  }
  return labels[fileType] || String(fileType || '附件').toUpperCase()
}

function auditActionLabel(action) {
  const labels = {
    create_alert: '创建告警',
    assign_alert: '分派告警',
    update_alert: '更新告警',
    delete_alert: '删除告警',
    delete_attachment: '删除附件',
    delete_entity: '删除实体',
    add_note: '添加记录',
    add_entity: '添加实体',
    upload_attachment: '上传附件'
  }
  return labels[action] || action
}

function auditSummary(item) {
  const after = item.after_data || {}
  if (item.action === 'assign_alert') {
    return `${after.from_owner || '未分派'} → ${after.to_owner || '未分派'}，分派人：${after.assigned_by || item.actor || '-'}`
  }
  if (item.action === 'update_alert') {
    return `状态：${after.status_label || after.status || '-'}，结论：${after.conclusion_label || after.conclusion || '未定'}，处理人：${after.owner || '-'}`
  }
  return after.title || after.original_name || after.content || item.target_id || '-'
}


async function loadTemplates() {
  try {
    const res = await getIncidentTemplates()
    if (res.success && res.data?.templates) templates.value = res.data.templates
  } catch (e) {
    ElMessage.error('设备字段模板加载失败: ' + e.message)
  }
}

// 指派选人目录：仅有指派/处置权限者能读取，失败静默降级为历史姓名候选
async function loadDirectory() {
  if (!auth.hasPerm('alert.assign') && !auth.hasPerm('subtask.manage')) return
  try {
    const res = await getAuthDirectory()
    if (res.success) directoryUsers.value = res.data?.users || []
  } catch (e) {
    /* 静默：目录不可用时仍可用历史姓名/自由输入 */
  }
}

function addOptionalField(key) {
  if (!selectedOptionalFieldKeys.value.includes(key)) {
    selectedOptionalFieldKeys.value.push(key)
  }
}

function removeOptionalField(key) {
  selectedOptionalFieldKeys.value = selectedOptionalFieldKeys.value.filter(item => item !== key)
  createForm.value[key] = ''
}

function newScreenshotSlot() {
  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    file: null,
    previewUrl: ''
  }
}

function addScreenshotSlot() {
  createScreenshotSlots.value.push(newScreenshotSlot())
}

function removeScreenshotSlot(id) {
  const slot = createScreenshotSlots.value.find(item => item.id === id)
  if (slot?.previewUrl) URL.revokeObjectURL(slot.previewUrl)
  createScreenshotSlots.value = createScreenshotSlots.value.filter(item => item.id !== id)
}

function setScreenshotFile(id, file) {
  if (!file?.type?.startsWith('image/')) {
    ElMessage.warning('截图字段仅支持图片文件')
    return
  }
  const slot = createScreenshotSlots.value.find(item => item.id === id)
  if (!slot) return
  if (slot.previewUrl) URL.revokeObjectURL(slot.previewUrl)
  slot.file = file
  slot.previewUrl = URL.createObjectURL(file)
}

function clipboardImage(event) {
  const file = Array.from(event.clipboardData?.items || [])
    .find(item => item.type.startsWith('image/'))
    ?.getAsFile()
  if (!file) return null
  const extension = file.type.split('/')[1]?.replace('jpeg', 'jpg') || 'png'
  return new File([file], `clipboard-${Date.now()}.${extension}`, { type: file.type })
}

function handleDetailPaste(event) {
  const file = clipboardImage(event)
  if (file) {
    event.preventDefault()
    let slot = createScreenshotSlots.value.find(item => !item.file)
    if (!slot) {
      slot = newScreenshotSlot()
      createScreenshotSlots.value.push(slot)
    }
    setScreenshotFile(slot.id, file)
    ElMessage.success('剪贴板图片已添加为告警截图')
    return
  }
}

function handleScreenshotPaste(event, id) {
  const file = clipboardImage(event)
  if (!file) return
  event.preventDefault()
  setScreenshotFile(id, file)
}

function openScreenshotPicker(event) {
  event.currentTarget.querySelector('input[type="file"]')?.click()
}

function handleScreenshotPick(event, id) {
  const file = event.target.files?.[0]
  event.target.value = ''
  if (file) setScreenshotFile(id, file)
}

function handleScreenshotDrop(event, id) {
  const file = Array.from(event.dataTransfer?.files || []).find(f => f.type?.startsWith('image/'))
  if (file) setScreenshotFile(id, file)
  else ElMessage.warning('截图字段仅支持图片文件')
}

function cleanupCreateAssets() {
  for (const slot of createScreenshotSlots.value) {
    if (slot.previewUrl) URL.revokeObjectURL(slot.previewUrl)
  }
  createScreenshotSlots.value = []
  createFiles.value = []
}

async function refreshAll() {
  await Promise.all([loadTemplates(), loadStats(), loadOperations(), loadAlerts(), loadDirectory()])
}

async function loadStats() {
  try {
    const res = await getIncidentStats()
    if (res.success) stats.value = res.data || {}
  } catch (e) {
    ElMessage.error('统计加载失败: ' + e.message)
  }
}

async function loadOperations() {
  try {
    const res = await getIncidentOperations(operationDays.value)
    if (res.success) operations.value = res.data || {}
  } catch (e) {
    ElMessage.error('运营概览加载失败: ' + e.message)
  }
}

async function loadAlerts() {
  loading.value = true
  try {
    const res = await listIncidentAlerts(filters.value)
    if (res.success) alerts.value = res.data.alerts || []
  } catch (e) {
    ElMessage.error('告警加载失败: ' + e.message)
  } finally {
    loading.value = false
  }
}

function handleSelectionChange(rows) {
  selectedRows.value = rows
}

async function runBatch(action, payload, successText) {
  if (!selectedAlertIds.value.length) return false
  batchLoading.value = true
  try {
    const res = await batchIncidentAlerts(selectedAlertIds.value, action, payload)
    if (!res.success) throw new Error(res.error || '批量操作失败')
    const errors = res.data?.errors || []
    if (errors.length) {
      ElMessage.warning(`${successText}，成功 ${res.data.updated} 条，失败 ${errors.length} 条`)
    } else {
      ElMessage.success(successText)
    }
    await refreshAll()
    return true
  } catch (e) {
    ElMessage.error('批量操作失败: ' + e.message)
    return false
  } finally {
    batchLoading.value = false
  }
}

async function batchAssign() {
  const owner = batchForm.value.owner.trim()
  if (!owner) {
    ElMessage.warning('请填写处理人')
    return
  }
  await runBatch('assign', { owner }, '批量分派完成')
}

async function batchChangeSeverity() {
  if (!batchForm.value.severity) {
    ElMessage.warning('请选择等级')
    return
  }
  await runBatch('severity', { severity: batchForm.value.severity }, '批量修改等级完成')
}

async function batchChangeStatus() {
  if (!batchForm.value.status) {
    ElMessage.warning('请选择状态')
    return
  }
  await runBatch('status', { status: batchForm.value.status }, '批量修改状态完成')
}

async function batchAddNote() {
  batchNoteDialogVisible.value = true
}

async function submitBatchNote() {
  const content = batchNoteDraft.value.trim()
  if (!content) return
  const succeeded = await runBatch('note', { content, note_type: 'batch' }, '批量备注完成')
  if (succeeded) {
    batchNoteDraft.value = ''
    batchNoteDialogVisible.value = false
  }
}

async function selectAlert(row) {
  try {
    const res = await getIncidentAlert(row.id)
    if (!res.success) return
    selectedAlert.value = res.data
    flowForm.value = {
      status: selectedAlert.value.status || 'pending',
      conclusion: selectedAlert.value.conclusion || ''
    }
    editForm.value = {
      reporter: selectedAlert.value.created_by || ''
    }
    blankResearchInputs()
    resetResearchFlags()
    clearAllStaged()
    subtaskForm.value = { title: '', team: '', assignee: '' }
    subtaskAdding.value = false
    handlersModel.value = [...(selectedAlert.value.handlers || [])]
    detailDialogVisible.value = true
  } catch (e) {
    ElMessage.error('详情加载失败: ' + e.message)
  }
}

function handleAlertRowClick(row, _column, event) {
  if (shouldIgnoreRowClick(event)) return
  selectAlert(row)
}

async function openAdjacentAlert(offset) {
  const target = alerts.value[selectedAlertIndex.value + offset]
  if (target) await selectAlert(target)
}

function openCreate() {
  cleanupCreateAssets()
  editingAlertId.value = null
  createForm.value = newCreateForm()
  createScreenshotSlots.value = [newScreenshotSlot()]
  selectedOptionalFieldKeys.value = []
  reportTime.value = new Date().toISOString()
  createDialogVisible.value = true
}

async function openEditAlert(alertOrId) {
  const id = typeof alertOrId === 'string' ? alertOrId : alertOrId.id
  const res = await getIncidentAlert(id)
  if (!res.success) return
  const alert = res.data
  const nf = alert.normalized_fields || {}
  cleanupCreateAssets()
  const form = newCreateForm()
  form.title = alert.title || ''
  form.source_category = alert.source_category || ''
  form.reporter = alert.created_by || ''
  form.source_system = alert.source_system || ''
  form.alert_type = alert.alert_type || ''
  form.severity = alert.severity || 'medium'
  form.description = alert.description || ''
  form.source_ip = nf.source_ip || ''
  form.destination_ip = nf.destination_ip || ''
  for (const key of deviceFieldKeys) {
    if (!fixedFieldKeys.has(key)) form[key] = nf[key] || ''
  }
  createForm.value = form
  createScreenshotSlots.value = [newScreenshotSlot()]
  createFiles.value = []
  reportTime.value = alert.created_at || ''
  // 不默认添加补充字段，由用户按需通过“添加字段”展开编辑
  selectedOptionalFieldKeys.value = []
  editingAlertId.value = alert.id
  editingStatus.value = alert.status || ''
  editOriginal.value = alert
  createDialogVisible.value = true
}

function addCreateFiles(fileList) {
  const files = Array.from(fileList || [])
  if (files.length) createFiles.value = [...createFiles.value, ...files]
}

function removeCreateFile(index) {
  createFiles.value = createFiles.value.filter((_, fileIndex) => fileIndex !== index)
}

function formatFileSize(size) {
  const bytes = Number(size) || 0
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

function handleCreateAttachmentPick(e) {
  addCreateFiles(e.target.files)
  e.target.value = ''
}

function handleCreateAttachmentDrop(e) {
  addCreateFiles(e.dataTransfer?.files)
}

function handleCreateAttachmentPaste(e) {
  const files = e.clipboardData?.files
  if (files && files.length) {
    e.preventDefault()
    addCreateFiles(files)
    ElMessage.success(`已从剪贴板添加 ${files.length} 个文件`)
  }
}

async function validateCreateForm({ requireComplete = false } = {}) {
  const f = createForm.value
  if (requireComplete) {
    const required = [
      [f.source_category, '安全设备'],
      [(f.title || '').trim(), '告警名称'],
      [(f.source_ip || '').trim(), '攻击 IP'],
      [(f.destination_ip || '').trim(), '被攻击 IP'],
      [(f.reporter || '').trim(), '上报人'],
      [(f.description || '').trim(), '告警详情'],
    ]
    for (const [val, label] of required) {
      if (!val) { ElMessage.warning(`请填写「${label}」`); return false }
    }
    for (const item of visibleOptionalFields.value) {
      const v = f[item.key]
      if (v === undefined || v === null || (typeof v === 'string' && !v.trim())) {
        ElMessage.warning(`请填写「${item.label}」`); return false
      }
    }
    const hasExistingImage = (editOriginal.value?.attachments || [])
      .some(item => item.file_type === 'image' && item.file_available !== false)
    const hasNewImage = createScreenshotSlots.value.some(slot => slot.file)
    if (!hasExistingImage && !hasNewImage) {
      ElMessage.warning('请至少上传一张告警截图')
      return false
    }
  }

  const selectedFiles = [
    ...createScreenshotSlots.value
      .filter(slot => slot.file)
      .map(slot => ({ file: slot.file, screenshot: true })),
    ...createFiles.value.map(file => ({ file, screenshot: false })),
  ]
  const fileError = await validateIncidentFiles(selectedFiles)
  if (fileError) {
    ElMessage.warning(fileError)
    return false
  }
  return true
}

function substantiveEditChanged(orig) {
  if (!orig) return false
  const nf = orig.normalized_fields || {}
  const f = createForm.value
  for (const k of ['title', 'source_category', 'source_system', 'alert_type', 'description']) {
    if ((orig[k] || '') !== (f[k] || '')) return true
  }
  for (const k of deviceFieldKeys) {
    if ((nf[k] || '') !== (f[k] || '')) return true
  }
  return false
}

function clearUploadedCreateFiles(uploaded = []) {
  for (const slot of createScreenshotSlots.value) {
    if (slot.previewUrl) URL.revokeObjectURL(slot.previewUrl)
  }
  createScreenshotSlots.value = [newScreenshotSlot()]
  createFiles.value = []
  if (editOriginal.value) {
    editOriginal.value = {
      ...editOriginal.value,
      attachments: [
        ...(editOriginal.value.attachments || []),
        ...uploaded,
      ],
    }
  }
}

async function submitCreate(action = 'edit') {
  const savingDraft = action === 'draft'
  const formallySubmitting = action === 'submit'
  if (!await validateCreateForm({ requireComplete: formallySubmitting })) return
  const isEditing = !!editingAlertId.value
  const wasStatus = editingStatus.value
  const orig = editOriginal.value
  const substChanged = isEditing ? substantiveEditChanged(orig) : false
  submitting.value = true
  try {
    const payload = { ...createForm.value, raw_text: createForm.value.description }
    let alert
    if (isEditing) {
      if (editingStatus.value === 'new') payload.submission_mode = 'draft'
      const res = await updateIncidentAlert(editingAlertId.value, payload)
      if (!res.success) throw new Error(res.error || '保存失败')
      alert = res.data
    } else {
      // 新告警始终先落为草稿；附件成功后才允许正式切换到“待分配”。
      payload.submission_mode = 'draft'
      const res = await createIncidentAlert(payload)
      if (!res.success) throw new Error(res.error || '创建失败')
      alert = res.data
      editingAlertId.value = alert.id
      editingStatus.value = 'new'
      editOriginal.value = alert
    }

    const files = [
      ...createScreenshotSlots.value.filter(slot => slot.file).map(slot => slot.file),
      ...createFiles.value,
    ]
    if (files.length) {
      const upload = await uploadIncidentAttachments(alert.id, files)
      const uploaded = upload.data?.attachments || []
      alert = {
        ...alert,
        attachments: [...(alert.attachments || []), ...uploaded],
      }
      clearUploadedCreateFiles(uploaded)
    }

    if (formallySubmitting) {
      const finalized = await updateIncidentAlert(alert.id, { submission_mode: 'submit' })
      if (!finalized.success) throw new Error(finalized.error || '正式创建失败')
      alert = finalized.data
    }

    createDialogVisible.value = false
    editingAlertId.value = null
    if (formallySubmitting) ElMessage.success('告警已创建，状态：待分配')
    else if (savingDraft) ElMessage.success('告警已保存，状态：创建中')
    else ElMessage.success('已保存')
    await refreshAll()
    await selectAlert(alert)
    // Step 2：已完成 + 有结论 的告警，编辑了关键信息 -> 提示是否重新研判
    if (isEditing && wasStatus === 'closed' && orig?.conclusion && substChanged) {
      let reopen = false
      try {
        await ElMessageBox.confirm(
          `该告警已研判为「${orig.conclusion_label || orig.conclusion}」。你修改了关键信息，是否需要重新研判？`,
          '证据已变更',
          { confirmButtonText: '重新研判', cancelButtonText: '保留结论', type: 'warning' }
        )
        reopen = true
      } catch { reopen = false }
      if (reopen) {
        const r = await setIncidentAlertStatus(alert.id, 'investigating', '证据变更后重新研判')
        if (r.success) {
          selectedAlert.value = r.data
          flowForm.value.status = r.data.status || ''
          ElMessage.success('已重新打开研判（研判中）')
          await Promise.all([loadAlerts(), loadStats()])
        }
      } else {
        await addIncidentNote(alert.id, '关键信息已变更，研判员选择保留原结论', 'manual')
        const fr = await getIncidentAlert(alert.id)
        if (fr.success) selectedAlert.value = fr.data
      }
    }
  } catch (e) {
    ElMessage.error('保存失败: ' + e.message)
  } finally {
    submitting.value = false
  }
}

async function changeStatus(status) {
  if (!selectedAlert.value) return
  const prev = selectedAlert.value.status
  const prevConclusion = selectedAlert.value.conclusion || ''
  try {
    const res = await setIncidentAlertStatus(selectedAlert.value.id, status, '')
    if (res.success) {
      selectedAlert.value = res.data
      flowForm.value.status = res.data.status || ''
      // 结论-状态一致性：进入应急响应可能作废矛盾的非事件类结论，同步下拉
      flowForm.value.conclusion = res.data.conclusion || ''
      if (prevConclusion && !res.data.conclusion) {
        ElMessage.warning('原结论与「应急响应中」不一致，已作废为「未定」，请重新研判定性')
      } else {
        ElMessage.success('状态已更新')
      }
      await Promise.all([loadAlerts(), loadStats()])
    }
  } catch (e) {
    // 完成门控 / 已完成锁定等校验失败：提示并回退下拉
    ElMessage.error(e.message || '状态更新失败')
    flowForm.value.status = prev
  }
}

function conclusionLabel(value) {
  return conclusionOptions.find(o => o.value === value)?.label || value || '未定'
}

function resetResearchFlags() {
  staleResearch.value = { key_evidence: false, handling_suggestion: false }
  responderHint.value = false
}

// 研判三框为纯输入用途：任何加载/刷新后都保持空白，正文只存于「研判记录」+ 快照列
function blankResearchInputs() {
  researchInputs.value = { key_evidence: '', handling_suggestion: '' }
}

function toggleResearchCollapsed() {
  researchCollapsed.value = !researchCollapsed.value
  localStorage.setItem('research_collapsed', researchCollapsed.value ? '1' : '0')
}

// 折叠时的每项状态：待复核 / 已记录 / 未填（看快照列，不看输入框）
function researchItemState(key) {
  if (staleResearch.value[key]) return 'stale'
  return (selectedAlert.value?.[key] || '').trim() ? 'done' : 'todo'
}

// 是否有待提交的研判输入（文字或暂存截图）——无则提交按钮置灰
const researchDirty = computed(() =>
  ['key_evidence', 'handling_suggestion'].some(
    k => (researchInputs.value[k] || '').trim()
      || (researchPending.value[k] || []).length
      || researchSubmission.value[k]
  )
)

function pulseStatus() {
  statusPulse.value = false
  // 下一帧再加类，确保动画重放
  requestAnimationFrame(() => {
    statusPulse.value = true
    setTimeout(() => { statusPulse.value = false }, 1200)
  })
}

// 结论翻转：归档旧研判内容 → 处置建议强耦合清空、依据/举证标记待复核
async function archiveAndSoftClear(prevConclusion, newConclusion) {
  const id = selectedAlert.value.id
  const parts = []
  for (const k of ['key_evidence', 'handling_suggestion']) {
    const v = (selectedAlert.value[k] || '').trim()
    if (v) parts.push(`${RESEARCH_LABELS[k]}：${v}`)
  }
  if (parts.length) {
    await addIncidentNote(
      id,
      `结论由「${conclusionLabel(prevConclusion)}」变更为「${conclusionLabel(newConclusion)}」，归档原研判内容：\n` + parts.join('\n'),
      'conclusion'
    )
  }
  // 处置建议强耦合（误报=加白、真实攻击=封禁，语义相反）：直接清空
  const upd = await updateIncidentAlert(id, { handling_suggestion: '' })
  if (upd.success) selectedAlert.value = upd.data
  researchInputs.value.handling_suggestion = ''
  // 研判依据（含举证）：保留原值，标记待复核
  staleResearch.value = {
    key_evidence: !!(selectedAlert.value.key_evidence || '').trim(),
    handling_suggestion: false
  }
}

function keepResearch(key) {
  staleResearch.value[key] = false
}

async function clearResearch(key) {
  if (!selectedAlert.value) return
  try {
    const upd = await updateIncidentAlert(selectedAlert.value.id, { [key]: '' })
    if (upd.success) selectedAlert.value = upd.data
    researchInputs.value[key] = ''
    staleResearch.value[key] = false
  } catch (e) {
    ElMessage.error('清空失败: ' + e.message)
  }
}

function openResponderAssign() {
  responderHint.value = false
  if (selectedAlert.value) openAssignDialog(selectedAlert.value)
}

function openSubtaskAdd() {
  subtaskForm.value = { title: '', team: '', assignee: '' }
  subtaskAdding.value = true
}

function cancelSubtaskAdd() {
  subtaskForm.value = { title: '', team: '', assignee: '' }
  subtaskAdding.value = false
}

function openSubtaskTab() {
  responderHint.value = false
  openSubtaskAdd()
}

async function refreshSelectedAlert() {
  if (!selectedAlert.value) return
  const fr = await getIncidentAlert(selectedAlert.value.id)
  if (fr.success) selectedAlert.value = fr.data
}

async function submitSubtask() {
  if (!selectedAlert.value || !canCoordinateSubtasks.value) return
  const title = subtaskForm.value.title.trim()
  if (!title) return
  try {
    const res = await addIncidentSubtask(selectedAlert.value.id, {
      title,
      team: subtaskForm.value.team.trim(),
      assignee: subtaskForm.value.assignee.trim()
    })
    if (!res.success) { ElMessage.error(res.error || '添加失败'); return }
    subtaskForm.value = { title: '', team: '', assignee: '' }
    subtaskAdding.value = false
    await refreshSelectedAlert()
    ElMessage.success('已添加处置子任务')
  } catch (e) {
    ElMessage.error('添加失败: ' + e.message)
  }
}

async function changeSubtaskStatus(st) {
  if (!canExecuteSubtask(st)) return
  try {
    const res = await updateIncidentSubtask(st.id, { status: st.status })
    if (!res.success) ElMessage.error(res.error || '更新失败')
    else ElMessage.success('子任务状态已更新')
  } catch (e) {
    ElMessage.error('更新失败: ' + e.message)
  } finally {
    await refreshSelectedAlert()
  }
}

async function removeSubtask(st) {
  if (!canCoordinateSubtasks.value) return
  try {
    await ElMessageBox.confirm(`删除处置子任务「${st.title}」？`, '确认删除', {
      confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning'
    })
  } catch { return }
  try {
    const res = await deleteIncidentSubtask(st.id)
    if (!res.success) { ElMessage.error(res.error || '删除失败'); return }
    await refreshSelectedAlert()
    ElMessage.success('已删除子任务')
  } catch (e) {
    ElMessage.error('删除失败: ' + e.message)
  }
}
async function changeConclusion(conclusion) {
  if (!selectedAlert.value) return
  const prev = selectedAlert.value.conclusion || ''
  const hasResearch = ['key_evidence', 'handling_suggestion']
    .some(k => (selectedAlert.value[k] || '').trim())
  const isFlip = !!prev && !!conclusion && conclusion !== prev
  // 结论翻转且已有研判内容：确认后软清空、待复核（历史归档到研判记录）
  if (isFlip && hasResearch) {
    try {
      await ElMessageBox.confirm(
        `研判结论由「${conclusionLabel(prev)}」改为「${conclusionLabel(conclusion)}」。` +
        `原「处置建议」将失效清空，「研判依据 / 举证信息」标记为待复核，原内容归档到研判记录。是否继续？`,
        '结论变更 · 重新研判',
        { confirmButtonText: '继续并重研', cancelButtonText: '取消', type: 'warning' }
      )
    } catch {
      flowForm.value.conclusion = prev // 取消：回退下拉
      return
    }
  }
  const prevStatus = selectedAlert.value.status
  try {
    // 出结论仅记录结论；三项信息在完成时校验（不在此强制）
    // 事件类结论由后端自动转入「应急响应中」
    const res = await setIncidentAlertConclusion(selectedAlert.value.id, conclusion)
    if (res.success) {
      selectedAlert.value = res.data
      flowForm.value.conclusion = res.data.conclusion || ''
      flowForm.value.status = res.data.status || ''
      if (isFlip && hasResearch) {
        await archiveAndSoftClear(prev, conclusion)
      }
      if (conclusion && res.data.status === 'responding' && prevStatus !== 'responding') {
        pulseStatus()
        if (EVENT_CONCLUSIONS.includes(conclusion)) responderHint.value = true
        ElMessage.success('已记录结论，自动转入应急响应处置')
      } else {
        ElMessage.success('研判结论已更新')
      }
      await Promise.all([loadAlerts(), loadStats()])
    }
  } catch (e) {
    ElMessage.error('结论更新失败: ' + e.message)
    flowForm.value.conclusion = prev
  }
}

// 粘贴/拖拽只把截图暂存并本地预览，不立即上传；点“确认”时随文字一并落库
function stageResearchImages(files, key) {
  const imgs = Array.from(files || []).filter(f => f.type?.startsWith('image/'))
  if (!imgs.length) return
  for (const f of imgs) {
    researchPending.value[key].push({ file: f, preview: URL.createObjectURL(f) })
  }
  ElMessage.success(`已暂存 ${imgs.length} 张截图，点“确认”与文字一并加入研判记录`)
}

function removeStaged(key, i) {
  const [item] = researchPending.value[key].splice(i, 1)
  if (item?.preview) URL.revokeObjectURL(item.preview)
}

function clearStaged(key) {
  for (const item of researchPending.value[key]) {
    if (item?.preview) URL.revokeObjectURL(item.preview)
  }
  researchPending.value[key] = []
}

function clearAllStaged() {
  for (const k of ['key_evidence', 'handling_suggestion']) clearStaged(k)
}

function handleResearchPaste(event, key = '') {
  const file = clipboardImage(event)
  if (file) {
    event.preventDefault()
    // 阻止冒泡到 window 上的证据区粘贴监听(handleEvidencePaste)，
    // 否则同一张图会被重复上传到「告警截图 / 证据」
    event.stopPropagation()
    stageResearchImages([file], key)
  }
}

function handleResearchDrop(event, key = '') {
  stageResearchImages(event.dataTransfer?.files, key)
}

// 记录单个研判项（上传暂存截图 + 更新快照列 + 追加研判记录），返回是否有新增
async function recordResearchItem(id, key) {
  const resumedSubmission = researchSubmission.value[key]
  const text = resumedSubmission?.text ?? (researchInputs.value[key] || '').trim()
  const pending = researchPending.value[key] || []
  if (!text && !pending.length && !resumedSubmission) return false
  const label = RESEARCH_LABELS[key]
  const prevText = (selectedAlert.value?.[key] || '').trim()
  // 批量上传并记录服务端 URL。后续写备注时即使会话失效，也不会重复上传已成功的截图。
  let urls = Array.isArray(resumedSubmission?.urls) ? [...resumedSubmission.urls] : []
  if (pending.length) {
    const resp = await uploadIncidentAttachments(
      id,
      pending.map(item => item.file),
      RESEARCH_SHOT_MARK
    )
    urls = [
      ...urls,
      ...(resp?.data?.attachments || []).map(item => item.url).filter(Boolean),
    ]
    clearStaged(key)
  }
  researchSubmission.value[key] = { text, urls }
  // 文字快照写入字段（用于完成门控）
  if (text && text !== prevText) {
    const upd = await updateIncidentAlert(id, { [key]: text })
    if (!upd.success) throw new Error(`${label}保存失败`)
  }
  let recorded = false
  if (resumedSubmission || (text && text !== prevText) || urls.length) {
    const header = text ? `${label}：${text}` : `${label} · 截图`
    const content = urls.length ? `${header}\n${urls.join('\n')}` : header
    await addIncidentNote(id, content, 'manual')
    recorded = true
  }
  researchSubmission.value[key] = null
  researchInputs.value[key] = ''
  return recorded
}

// 统一提交：非空项记入研判记录；仍缺失的必填项提示用户
async function submitResearch() {
  if (!selectedAlert.value) return
  const id = selectedAlert.value.id
  const keys = ['key_evidence', 'handling_suggestion']
  try {
    let recorded = 0
    for (const key of keys) {
      if (await recordResearchItem(id, key)) recorded++
    }
    const fresh = await getIncidentAlert(id)
    if (fresh.success) selectedAlert.value = fresh.data
    await loadAlerts()
    // 校验三项必填（看快照列，不看已清空的输入框）
    const missing = keys.filter(k => !((selectedAlert.value?.[k] || '').trim())).map(k => RESEARCH_LABELS[k])
    if (missing.length) {
      ElMessage.warning(`研判信息尚未填写完整，还需补充：${missing.join('、')}`)
    } else if (recorded) {
      ElMessage.success('研判信息已提交')
    } else {
      ElMessage.info('研判信息均已记录，无新增内容')
    }
  } catch (e) {
    ElMessage.error('提交失败: ' + e.message)
  }
}

function openAssignDialog(alert) {
  assignTarget.value = alert
  assignNewHandler.value = []
  assignDialogVisible.value = true
}

async function addHandler() {
  if (!assignTarget.value || !assignNewHandler.value.length || assignSubmitting.value) return
  const selected = assignNewHandler.value
    .map(name => String(name || '').trim())
    .filter(Boolean)
  const merged = Array.from(new Set([...(assignTarget.value.handlers || []), ...selected]))
  assignSubmitting.value = true
  try {
    const res = await setIncidentHandlers(assignTarget.value.id, merged)
    if (!res.success) throw new Error(res.error || '指派失败')

    assignTarget.value = res.data
    if (selectedAlert.value?.id === res.data.id) {
      selectedAlert.value = res.data
      handlersModel.value = [...(res.data.handlers || [])]
      flowForm.value.status = res.data.status || ''
      flowForm.value.conclusion = res.data.conclusion || ''
    }
    ElMessage.success('处理人已更新')
    assignNewHandler.value = []
    await Promise.all([loadAlerts(), loadStats()])
  } catch (e) {
    ElMessage.error(e.message || '指派失败')
  } finally {
    assignSubmitting.value = false
  }
}

async function removeHandlerFn(name) {
  if (!assignTarget.value || assignSubmitting.value) return
  const remaining = (assignTarget.value.handlers || []).filter(h => h !== name)
  assignSubmitting.value = true
  try {
    const res = await setIncidentHandlers(assignTarget.value.id, remaining)
    if (!res.success) throw new Error(res.error || '移除处理人失败')
    assignTarget.value = res.data
    if (selectedAlert.value?.id === res.data.id) {
      selectedAlert.value = res.data
      handlersModel.value = [...(res.data.handlers || [])]
      flowForm.value.status = res.data.status || ''
      flowForm.value.conclusion = res.data.conclusion || ''
    }
    ElMessage.success(`已移除处理人：${name}`)
    await Promise.all([loadAlerts(), loadStats()])
  } catch (e) {
    ElMessage.error(e.message || '移除处理人失败')
  } finally {
    assignSubmitting.value = false
  }
}

function openRejectDialog() {
  rejectReason.value = ''
  rejectDialogVisible.value = true
}

function openReopenDialog() {
  reopenForm.value = { conclusion: '', reason: '' }
  reopenDialogVisible.value = true
}

async function submitReopen() {
  if (!selectedAlert.value || !reopenForm.value.conclusion) return
  const prevConclusion = selectedAlert.value.conclusion || ''
  const newConclusion = reopenForm.value.conclusion
  try {
    const res = await reopenIncidentAlert(selectedAlert.value.id, newConclusion, reopenForm.value.reason.trim())
    if (!res.success) { ElMessage.error(res.error || '重新研判失败'); return }
    selectedAlert.value = res.data
    flowForm.value.status = res.data.status || ''
    flowForm.value.conclusion = res.data.conclusion || ''
    handlersModel.value = [...(res.data.handlers || [])]
    blankResearchInputs()
    // 归档旧研判内容 + 软清空（复用活动态翻转逻辑）
    await archiveAndSoftClear(prevConclusion, newConclusion)
    reopenDialogVisible.value = false
    // 事件类结论已在后端转应急响应：状态动画 + 处理人建议
    if (res.data.status === 'responding') {
      pulseStatus()
      if (EVENT_CONCLUSIONS.includes(newConclusion)) responderHint.value = true
    }
    ElMessage.success(`已重新研判，进入第 ${res.data.round} 轮（${res.data.status_label}）`)
    await Promise.all([loadAlerts(), loadStats()])
  } catch (e) {
    ElMessage.error('重新研判失败: ' + e.message)
  }
}

async function submitReject() {
  if (!selectedAlert.value) return
  const res = await rejectIncidentAlert(selectedAlert.value.id, rejectReason.value.trim())
  if (res.success) {
    selectedAlert.value = res.data
    flowForm.value.status = res.data.status || ''
    flowForm.value.conclusion = res.data.conclusion || ''
    handlersModel.value = [...(res.data.handlers || [])]
    blankResearchInputs()
    resetResearchFlags()
    rejectDialogVisible.value = false
    ElMessage.success(`已驳回并清空重启，回退至待分配（第 ${res.data.round} 轮）`)
    await Promise.all([loadAlerts(), loadStats()])
  } else {
    ElMessage.error(res.error || '驳回失败')
  }
}

async function saveHandlers() {
  if (!selectedAlert.value) return
  const prevRound = selectedAlert.value.round || 1
  const res = await setIncidentHandlers(selectedAlert.value.id, handlersModel.value)
  if (res.success) {
    selectedAlert.value = res.data
    handlersModel.value = [...(res.data.handlers || [])]
    flowForm.value.status = res.data.status || ''
    flowForm.value.conclusion = res.data.conclusion || ''
    blankResearchInputs()
    // 仅在真正重开（round+1）时才清场；普通增删处理人不应清掉待复核/应急处置人提示(responderHint)
    if ((res.data.round || 1) > prevRound) {
      resetResearchFlags()
      ElMessage.success(`已重新指派并重开研判，进入第 ${res.data.round} 轮（原结论与研判信息已清空）`)
    } else {
      ElMessage.success('当前处理人已更新')
    }
    await Promise.all([loadAlerts(), loadStats()])
  }
}

async function saveReporter() {
  if (!selectedAlert.value) return
  const res = await updateIncidentAlert(selectedAlert.value.id, { created_by: editForm.value.reporter })
  if (res.success) {
    selectedAlert.value = res.data
    await loadAlerts()
  }
}

async function submitEntity() {
  if (!selectedAlert.value || !entityForm.value.value.trim()) return
  const res = await addIncidentEntity(selectedAlert.value.id, entityForm.value)
  if (res.success) {
    entityForm.value.value = ''
    await selectAlert(selectedAlert.value)
  }
}

async function removeEntity(entity) {
  const res = await deleteIncidentEntity(entity.id)
  if (res.success) await selectAlert(selectedAlert.value)
}

async function refreshCorrelation() {
  if (!selectedAlert.value?.id) return
  correlationLoading.value = true
  try {
    const res = await getIncidentCorrelation(selectedAlert.value.id, 20)
    if (!res.success) throw new Error(res.error || '关联分析失败')
    selectedAlert.value.correlation = res.data || {}
    selectedAlert.value.related = res.data?.related_alerts || []
    ElMessage.success('关联分析已刷新')
  } catch (e) {
    ElMessage.error('关联分析失败: ' + e.message)
  } finally {
    correlationLoading.value = false
  }
}

async function uploadFiles(fileList) {
  const files = Array.from(fileList || [])
  if (!selectedAlert.value || files.length === 0) return
  pendingEvidenceUploads.value = [...files]
  try {
    for (const file of files) {
      await uploadIncidentAttachment(selectedAlert.value.id, file)
      pendingEvidenceUploads.value = pendingEvidenceUploads.value.filter(item => item !== file)
    }
    ElMessage.success(`已上传 ${files.length} 个附件`)
    await selectAlert(selectedAlert.value)
  } catch (err) {
    ElMessage.error('上传失败: ' + err.message)
  }
}

async function handleAttachmentPick(e) {
  const files = e.target.files
  e.target.value = ''
  await uploadFiles(files)
}

function handleEvidenceDrop(e) {
  isDragging.value = false
  uploadFiles(e.dataTransfer?.files)
}

function onListDragEnter() {
  listDragDepth.value += 1
  isListDragging.value = true
}
function onListDragLeave() {
  listDragDepth.value = Math.max(0, listDragDepth.value - 1)
  if (listDragDepth.value === 0) isListDragging.value = false
}

async function processQuickCreates() {
  try {
    let firstId = null
    for (const item of [...pendingQuickCreates.value]) {
      const file = item.file
      const name = file.name.replace(/\.[^.]+$/, '') || '未命名'
      if (!item.alertId) {
        const res = await createIncidentAlert({
          title: `截图告警 - ${name}`,
          source_category: 'other',
          source_system: '截图快速录入',
          severity: 'medium',
        })
        if (!res.success) throw new Error(res.error || '快速建单失败')
        item.alertId = res.data.id
      }
      if (!firstId) firstId = item.alertId
      await uploadIncidentAttachment(item.alertId, file)
      pendingQuickCreates.value = pendingQuickCreates.value.filter(entry => entry !== item)
    }
    ElMessage.success('截图快速建单完成')
    await refreshAll()
    if (firstId) await selectAlert({ id: firstId })
  } catch (err) {
    ElMessage.error('快速建单失败: ' + err.message)
  }
}

async function handleListDrop(e) {
  isListDragging.value = false
  listDragDepth.value = 0
  const files = Array.from(e.dataTransfer?.files || []).filter(f => f.type?.startsWith('image/'))
  if (!files.length) {
    if (e.dataTransfer?.files?.length) ElMessage.warning('快速建单仅支持图片截图')
    return
  }
  pendingQuickCreates.value = files.map(file => ({ file, alertId: '' }))
  await processQuickCreates()
}

async function removeAttachment(att) {
  if (!att) return
  try {
    await ElMessageBox.confirm(
      `确定删除附件「${att.original_name}」？删除后不可恢复。`,
      '删除附件',
      {
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
        type: 'warning',
        confirmButtonClass: 'el-button--danger',
      }
    )
  } catch {
    return
  }
  const res = await deleteIncidentAttachment(att.id)
  if (res.success) {
    ElMessage.success('附件已删除')
    await selectAlert(selectedAlert.value)
  }
}

async function copyAlertNo(value) {
  if (!value) return
  try {
    await navigator.clipboard.writeText(value)
  } catch (_) {
    const input = document.createElement('textarea')
    input.value = value
    input.style.position = 'fixed'
    input.style.opacity = '0'
    document.body.appendChild(input)
    input.select()
    document.execCommand('copy')
    input.remove()
  }
  ElMessage.success(`已复制告警编号：${value}`)
}

async function openAttachment(att) {
  try {
    await downloadIncidentAttachment(att)
  } catch (err) {
    ElMessage.error(err.message || '附件下载失败')
  }
}

async function handleEvidencePaste(event) {
  if (!detailDialogVisible.value || !selectedAlert.value) return
  // 研判信息区（研判依据/举证信息/处置建议）内的粘贴由 handleResearchPaste 落到研判记录，
  // 证据区监听不接管，避免同一张图重复上传到「告警截图 / 证据」
  if (event.target?.closest?.('.detail-description')) return
  const file = clipboardImage(event)
  if (!file) return
  try {
    await uploadIncidentAttachment(selectedAlert.value.id, file)
    ElMessage.success('剪贴板截图已上传')
    await selectAlert(selectedAlert.value)
  } catch (err) {
    ElMessage.error('上传失败: ' + err.message)
  }
}

watch(detailDialogVisible, (open) => {
  if (open) window.addEventListener('paste', handleEvidencePaste)
  else window.removeEventListener('paste', handleEvidencePaste)
})
onBeforeUnmount(() => window.removeEventListener('paste', handleEvidencePaste))

async function removeSelected() {
  if (!selectedAlert.value) return
  try {
    await ElMessageBox.confirm(
      `将永久删除告警「${selectedAlert.value.title}」及其全部截图、附件与研判记录，此操作不可恢复。`,
      '确认删除告警',
      {
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
        type: 'warning',
        confirmButtonClass: 'el-button--danger',
      }
    )
  } catch {
    return
  }
  const res = await deleteIncidentAlert(selectedAlert.value.id)
  if (res.success) {
    selectedAlert.value = null
    detailDialogVisible.value = false
    ElMessage.success('已删除')
    await refreshAll()
  }
}

async function exportMarkdown() {
  if (!selectedAlert.value) return
  try {
    const text = await exportIncidentAlertMarkdown(selectedAlert.value.id)
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `alert-${selectedAlert.value.id}.md`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    ElMessage.error('导出失败: ' + e.message)
  }
}

async function exportOperationsCsv() {
  try {
    const text = await exportIncidentOperationsCsv(operationDays.value)
    const blob = new Blob([text], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `incident-operations-${operationDays.value}d.csv`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    ElMessage.error('运营报表导出失败: ' + e.message)
  }
}

// —— 运营概览「滚动隐藏」：浏览告警队列向下滚动时收起顶部运营概览，向上滚动 / 回到顶部时恢复 ——
const alertTableRef = ref(null)
const opsHidden = ref(false)
let opsScrollEl = null
let opsLastTop = 0

function handleQueueScroll() {
  if (!opsScrollEl) return
  const top = opsScrollEl.scrollTop
  if (top <= 4) {
    opsHidden.value = false             // 回到顶部：恢复显示
  } else if (top > opsLastTop + 4 && top > 40) {
    opsHidden.value = true              // 向下滚动且已滚过 40px：收起
  } else if (top < opsLastTop - 4) {
    opsHidden.value = false             // 向上滚动：恢复
  }
  opsLastTop = top
}

function bindQueueScroll() {
  const el = (alertTableRef.value && alertTableRef.value.$el
    && alertTableRef.value.$el.querySelector('.el-scrollbar__wrap'))
    || document.querySelector('.alert-table .el-scrollbar__wrap')
  if (el && el !== opsScrollEl) {
    if (opsScrollEl) opsScrollEl.removeEventListener('scroll', handleQueueScroll)
    opsScrollEl = el
    opsLastTop = el.scrollTop
    el.addEventListener('scroll', handleQueueScroll, { passive: true })
  }
}

// 列表数据变化后（首次渲染 / 重新查询）：复位为显示并（重新）确认滚动容器
watch(alerts, () => {
  opsHidden.value = false
  opsLastTop = 0
  nextTick(bindQueueScroll)
})

onMounted(async () => {
  window.addEventListener('capture-session-resume', captureSessionResume)
  const restored = await restoreSessionResume()
  if (!restored) await refreshAll()
  nextTick(bindQueueScroll)
})

onBeforeUnmount(() => {
  window.removeEventListener('capture-session-resume', captureSessionResume)
  if (opsScrollEl) opsScrollEl.removeEventListener('scroll', handleQueueScroll)
})
</script>

<style scoped>
.analysis-page { display: flex; flex-direction: column; height: 100%; min-height: 0; }
.kibana-panel { background: #fff; border: 1px solid #D3DAE6; border-radius: 6px; overflow: hidden; }
/* 运营概览「滚动隐藏」：grid-template-rows 1fr→0fr 按真实高度平滑收合，隐藏时连同 8px 间距一起归零 */
.ops-collapse { display: grid; grid-template-rows: 1fr; margin-bottom: 8px; min-height: 0; transition: grid-template-rows .26s ease, margin-bottom .26s ease, opacity .2s ease; }
.ops-collapse > .operations-panel { min-height: 0; overflow: hidden; }
.ops-collapse--hidden { grid-template-rows: 0fr; margin-bottom: 0; opacity: 0; pointer-events: none; }
.stats-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.stat-card { background: #fff; border: 1px solid #D3DAE6; border-radius: 6px; padding: 12px 14px; display: flex; flex-direction: column; gap: 4px; }
.stat-label { color: #69707D; font-size: 12px; }
.stat-card strong { font-size: 24px; color: #1B1D21; }
.operations-panel { display: flex; flex-direction: column; }
.operations-header { display: flex; align-items: center; flex-wrap: wrap; gap: 6px 16px; padding: 6px 12px; border-bottom: 1px solid #E8EDF3; }
.ops-title { flex-shrink: 0; }
.operations-actions { display: flex; align-items: center; gap: 8px; }
.operations-actions .el-select { width: 110px; }
.ops-compact { display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 18px; padding: 0; flex: 1 1 auto; min-width: 0; }
.ops-compact span { color: #69707D; font-size: 13px; }
.ops-compact strong { color: #1B1D21; font-size: 15px; margin-left: 4px; }
.ops-compact-sep { color: #B4BAC4; font-size: 12px; border-left: 1px solid #E8EDF3; padding-left: 20px; }
.empty-inline { color: #8B92A0; justify-content: flex-start !important; }
.analysis-main { display: flex; flex: 1; min-height: 0; }
.analysis-list { display: flex; flex: 1; flex-direction: column; min-width: 0; min-height: 0; }
.panel-header { padding: 8px 12px; border-bottom: 1px solid #E8EDF3; display: flex; flex-direction: row; align-items: center; flex-wrap: wrap; gap: 8px 16px; }
.panel-heading { flex-shrink: 0; }
.panel-heading-row { display: flex; align-items: center; justify-content: flex-start; gap: 16px; flex-shrink: 0; }
.panel-title { font-weight: 700; color: #1B1D21; }
.analysis-list { position: relative; }
.analysis-list.list-dragging { outline: 2px dashed #006DE0; outline-offset: -4px; }
.list-drop-overlay { position: absolute; inset: 0; z-index: 30; display: flex; align-items: center; justify-content: center; background: rgba(232, 241, 252, 0.88); border-radius: 8px; pointer-events: none; }
.list-drop-card { display: flex; flex-direction: column; align-items: center; gap: 8px; color: #006DE0; font-size: 15px; font-weight: 600; }
.list-drop-card .el-icon { font-size: 42px; }
.list-drop-card small { font-weight: 400; color: #5A6069; font-size: 12px; }
.panel-subtitle { margin-top: 3px; color: #69707D; font-size: 12px; }
.queue-tabs { display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-start; }
.queue-tabs button { border: 1px solid #D3DAE6; border-radius: 4px; background: #fff; color: #5A6069; cursor: pointer; padding: 5px 8px; display: inline-flex; align-items: center; gap: 6px; font-size: 12px; }
.queue-tabs button:hover { border-color: #006DE0; color: #006DE0; }
.queue-tabs button.active { background: #E8F1FC; border-color: #006DE0; color: #006DE0; font-weight: 700; }
.queue-tabs strong { font-size: 11px; color: inherit; }
.panel-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; justify-content: flex-end; flex: 1 1 auto; min-width: 0; }
.panel-actions > .el-select { width: 130px; }
.filter-keyword { width: 310px; }
.filter-person { width: 110px; }
.batch-toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 8px 12px; border-bottom: 1px solid #E8EDF3; background: #FAFBFD; }
.batch-toolbar > span { color: #5A6069; font-size: 12px; font-weight: 700; margin-right: 4px; }
.batch-owner { width: 130px; }
.batch-select { width: 120px; }
.alert-table { flex: 1; min-height: 0; }
.alert-no { border: 0; padding: 0; background: transparent; color: #006DE0; font-family: Consolas, "SFMono-Regular", monospace; font-size: 12px; cursor: copy; white-space: nowrap; }
.alert-no:hover { color: #004EAA; text-decoration: underline; }
.alert-title-cell { display: flex; align-items: center; min-width: 0; gap: 8px; font-weight: 600; color: #1B1D21; }
.alert-title-cell > span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.muted-line { color: #7A8391; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.severity-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; background: #D6A000; }
.severity-dot--critical { background: #8B0000; }
.severity-dot--high { background: #BD271E; }
.severity-dot--medium { background: #D6A000; }
.severity-dot--low, .severity-dot--info { background: #017D73; }
.detail-dialog-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; width: 100%; }
.detail-dialog-header.is-shrunk { justify-content: flex-end; }
.detail-dialog-header.is-shrunk .detail-dialog-heading { display: none; }
.detail-dialog-title { color: #1B1D21; font-size: 16px; font-weight: 700; }
.detail-dialog-counter { margin-top: 3px; color: #69707D; font-size: 12px; }
.detail-navigation { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.detail-dialog-body { width: min(1440px, 100%); min-height: 0; margin: 0 auto; padding: 0 20px 24px; }
.detail-header { padding: 14px 16px; border-bottom: 1px solid #E8EDF3; display: flex; justify-content: space-between; gap: 12px; }
.detail-header > div:first-child { flex: 1; min-width: 0; }
.detail-title { display: flex; align-items: center; min-width: 0; gap: 8px; font-size: 16px; font-weight: 700; color: #1B1D21; }
.detail-title > span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.detail-alert-no { flex-shrink: 0; font-size: 13px; }
.detail-meta { margin-top: 5px; font-size: 12px; color: #69707D; }
.detail-actions { display: flex; gap: 8px; align-items: flex-start; }
.severity-badge { display: inline-flex; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; color: #fff; background: #D6A000; text-transform: uppercase; }
.severity-badge--critical { background: #8B0000; }
.severity-badge--high { background: #BD271E; }
.severity-badge--medium { background: #D6A000; }
.severity-badge--low, .severity-badge--info { background: #017D73; }
.detail-grid { display: grid; grid-template-columns: 220px 1fr; gap: 12px; padding: 12px; }
.detail-card { border: 1px solid #E8EDF3; border-radius: 6px; padding: 12px; background: #FAFBFD; }
.detail-overview { margin-bottom: 12px; }
.alert-desc-text { margin-top: 10px; padding: 8px 10px; border: 1px solid #E8EDF3; border-radius: 6px; background: #fff; font-size: 12px; color: #5A6069; line-height: 1.6; white-space: pre-wrap; word-break: break-word; user-select: text; }
.alert-detail-fields { display: flex; flex-direction: column; gap: 4px; }
.alert-detail-row { display: flex; gap: 8px; font-size: 12px; line-height: 1.6; user-select: text; }
.alert-detail-row .adr-label { color: #8B92A0; flex-shrink: 0; min-width: 72px; }
.alert-detail-row .adr-value { color: #1B1D21; word-break: break-all; user-select: text; }
.card-title { font-weight: 700; margin-bottom: 10px; color: #1B1D21; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.template-label { color: #006DE0; background: #E8F1FC; border-radius: 10px; padding: 2px 7px; font-size: 10px; font-weight: 600; }
.field-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 12px; }
.field-grid div { min-width: 0; }
.field-grid span { display: block; color: #69707D; font-size: 12px; }
.field-grid strong { display: block; color: #1B1D21; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.field-wide { grid-column: span 2; }
.empty-fields { grid-column: span 2; color: #8B92A0; font-weight: 400; font-size: 12px; padding: 10px 0; }
.detail-main { display: flex; flex-direction: column; gap: 12px; padding: 12px; }
.detail-info-row { display: grid; grid-template-columns: 280px minmax(0, 1fr); gap: 12px; align-items: stretch; }
.info-grid .el-input { margin-top: 2px; }
.evidence-panel { border: 1px solid #E8EDF3; border-radius: 6px; padding: 12px; background: #FAFBFD; min-width: 0; }
.evidence-uploader { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
.evidence-uploader > span { color: #69707D; font-size: 12px; }
.evidence-gallery { display: flex; flex-direction: column; gap: 12px; }
.evidence-gallery { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-start; }
.evidence-shot { position: relative; max-width: 100%; border: 1px solid #E8EDF3; border-radius: 6px; overflow: hidden; background: #fff; }
.evidence-shot .el-image { display: block; max-width: 100%; cursor: zoom-in; }
.evidence-shot :deep(.el-image__inner) { display: block; width: auto; height: auto; max-width: 100%; max-height: 560px; object-fit: contain; }
.attachment-delete.evidence-shot-delete { top: 8px; right: 8px; color: #fff; background: rgba(20, 28, 38, .68); border-radius: 4px; padding: 5px; opacity: .78; transition: opacity .15s ease, background .15s ease; }
.evidence-shot:hover .evidence-shot-delete,
.evidence-shot-delete:focus-visible { opacity: 1; }
.attachment-delete.evidence-shot-delete:hover { background: rgba(192, 57, 43, .9); }
.evidence-panel { transition: border-color .15s, background .15s, box-shadow .15s; }
.evidence-panel.is-dragging { border-color: #006DE0; background: #F2F8FE; box-shadow: inset 0 0 0 2px #CFE4FB; }
.evidence-drop-hint { margin-bottom: 12px; padding: 6px 10px; border-radius: 6px; background: #E8F1FC; color: #006DE0; font-size: 12px; text-align: center; }
.evidence-empty { display: flex; flex-direction: column; align-items: center; gap: 6px; border: 1px dashed #C7D0DE; border-radius: 8px; padding: 30px 16px; text-align: center; color: #8B92A0; font-size: 13px; background: #FCFDFE; cursor: pointer; transition: border-color .15s, background .15s; }
.evidence-empty:hover { border-color: #006DE0; background: #F6FAFE; }
.evidence-empty-icon { font-size: 34px; color: #9FB6D6; }
.evidence-empty-title { font-size: 14px; font-weight: 600; color: #5A6069; }
.evidence-empty-sub { font-size: 12px; color: #9098A4; }
.evidence-files { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.evidence-file-chip { position: relative; display: flex; align-items: center; gap: 6px; padding: 6px 28px 6px 10px; border: 1px solid #E8EDF3; border-radius: 6px; background: #fff; font-size: 12px; color: #1B1D21; max-width: 240px; cursor: pointer; transition: border-color .15s, background .15s; }
.evidence-file-chip:hover { border-color: #006DE0; background: #F2F8FE; color: #006DE0; }
.evidence-file-chip:hover small { color: #006DE0; }
.evidence-file-chip.is-missing { border-color: #E6B9B6; background: #FFF7F6; color: #A33A32; cursor: not-allowed; }
.evidence-file-chip.is-missing:hover { border-color: #D9908A; background: #FFF1F0; color: #A33A32; }
.evidence-file-chip.is-missing small { color: #A33A32; }
.evidence-file-chip > span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.evidence-file-chip small { color: #8B92A0; flex-shrink: 0; }
.evidence-file-chip .attachment-delete { position: absolute; top: 50%; right: 4px; transform: translateY(-50%); background: transparent; color: #C0392B; padding: 2px; }
.detail-tabs { flex: 1; min-height: 0; padding: 0 12px 12px; overflow: auto; }
.note-editor { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }
.note-editor .el-button { align-self: flex-end; }
.timeline { display: flex; flex-direction: column; gap: 8px; }
.timeline-item { border-left: 3px solid #D3DAE6; padding: 6px 10px; background: #FAFBFD; }
.timeline-time { color: #69707D; font-size: 12px; margin-bottom: 4px; }
.timeline-content { color: #1B1D21; white-space: pre-wrap; }
.timeline-shots { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.timeline-shot { width: 96px; height: 72px; border: 1px solid #E8EDF3; border-radius: 4px; overflow: hidden; cursor: pointer; background: #fff; }
.research-staged { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.research-staged-item { position: relative; width: 64px; height: 48px; border: 1px solid #E8EDF3; border-radius: 4px; overflow: hidden; background: #fff; }
.research-staged-item img { width: 100%; height: 100%; object-fit: cover; }
.staged-remove { position: absolute; top: 0; right: 0; width: 16px; height: 16px; line-height: 14px; text-align: center; border: none; background: rgba(0,0,0,.55); color: #fff; cursor: pointer; font-size: 12px; border-bottom-left-radius: 4px; padding: 0; }
.tab-count { display: inline-block; min-width: 16px; padding: 0 5px; margin-left: 4px; border-radius: 8px; background: #E8613C; color: #fff; font-size: 11px; line-height: 16px; text-align: center; }
.subtask-bar { margin-bottom: 10px; }
.subtask-card .subtask-optional { font-weight: 400; font-size: 12px; color: #8B92A0; margin-left: 8px; }
.subtask-add { display: flex; gap: 6px; margin-bottom: 10px; }
.subtask-add .subtask-narrow { width: 118px; flex-shrink: 0; }
.subtask-list { display: flex; flex-direction: column; gap: 6px; }
.subtask-item { display: flex; align-items: center; justify-content: space-between; gap: 8px; border: 1px solid #E8EDF3; border-left: 3px solid #D3DAE6; border-radius: 6px; padding: 8px 10px; background: #FAFBFD; }
.subtask-item.st-doing { border-left-color: #E6A23C; }
.subtask-item.st-done { border-left-color: #67C23A; background: #F6FBF3; }
.subtask-main { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; min-width: 0; }
.subtask-title { color: #1B1D21; font-size: 13px; word-break: break-word; }
.subtask-title.done { color: #8B92A0; text-decoration: line-through; }
.subtask-tag { font-size: 11px; padding: 1px 6px; border-radius: 4px; }
.subtask-tag.team { background: #EAF2FE; color: #2B6CB0; border: 1px solid #CFE0F7; }
.subtask-tag.person { background: #F0EEFB; color: #5B4BB0; border: 1px solid #DAD3F3; }
.subtask-ops { display: flex; align-items: center; gap: 6px; flex-shrink: 0; }
.subtask-status { width: 96px; }
.subtask-del { border: none; background: transparent; color: #C0392B; cursor: pointer; padding: 2px 4px; display: inline-flex; align-items: center; }
.round-divider { display: flex; align-items: center; gap: 8px; margin: 6px 0 2px; color: #C0651A; font-size: 12px; font-weight: 700; }
.round-divider::before, .round-divider::after { content: ''; flex: 1; height: 1px; background: #F0C9A6; }
.reject-hint { margin: 0 0 12px; padding: 10px 12px; background: #FDF6EC; border: 1px solid #F5DAB1; border-radius: 6px; color: #915B1D; font-size: 13px; line-height: 1.6; }
.reopen-hint { margin: 0 0 12px; padding: 10px 12px; background: #FEF0F0; border: 1px solid #FBC4C4; border-radius: 6px; color: #A23A3A; font-size: 13px; line-height: 1.6; }
.reopen-field { display: flex; flex-direction: column; gap: 4px; margin-bottom: 10px; }
.reopen-field > span { color: #69707D; font-size: 12px; }
.need-flag { font-style: normal; font-size: 11px; font-weight: 600; color: #C0651A; background: #FDF6EC; border: 1px solid #F5DAB1; border-radius: 4px; padding: 0 5px; margin-left: 4px; }
.recorded-flag { font-style: normal; font-size: 11px; font-weight: 600; color: #5B9A6B; background: #EEF7F0; border: 1px solid #CDE8D5; border-radius: 4px; padding: 0 5px; margin-left: 4px; }
.research-fill-head { display: flex; align-items: center; gap: 8px; margin: 6px 0 8px; }
.research-fill-title { font-size: 13px; font-weight: 600; color: #33507A; }
.research-fill-head > .el-button { margin-left: auto; flex-shrink: 0; }
.research-title-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.research-title-row .el-button { flex-shrink: 0; }
.research-mini-row { margin: 0 0 8px; }
.research-mini { display: flex; gap: 6px; flex-wrap: wrap; }
.research-mini-item { font-size: 11px; padding: 1px 8px; border-radius: 10px; border: 1px solid #E0E0E0; color: #8B92A0; background: #F5F6F8; }
.research-mini-item.done { color: #5B9A6B; background: #EEF7F0; border-color: #CDE8D5; }
.research-mini-item.todo { color: #C0651A; background: #FDF6EC; border-color: #F5DAB1; }
.research-mini-item.stale { color: #B4600B; background: #FFF4E3; border-color: #F3CE93; }
.research-submit-bar { grid-column: 1 / -1; display: flex; justify-content: flex-end; margin-top: 4px; }
.closure-item.is-missing { border-left: 3px solid #E6A23C; }
.closed-lock-hint { margin: 0 0 10px; padding: 8px 12px; background: #EEF3FA; border: 1px solid #C9DAF0; border-radius: 6px; color: #33507A; font-size: 12.5px; line-height: 1.6; }
.stale-flag { font-style: normal; font-size: 11px; font-weight: 600; color: #B4600B; background: #FFF4E3; border: 1px solid #F3CE93; border-radius: 4px; padding: 0 5px; margin-left: 4px; }
.closure-item.is-stale { border-color: #F3CE93; background: #FFFBF3; }
.stale-actions { display: flex; align-items: center; gap: 4px; margin: 0 0 6px; }
.stale-actions .stale-note { display: inline; font-style: normal; flex: 1; color: #B4600B; font-size: 11.5px; margin: 0; }
.responder-hint { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin: 0 0 10px; padding: 9px 12px; background: #FEF0E6; border: 1px solid #F6C9A6; border-radius: 6px; color: #9A4A16; font-size: 12.5px; line-height: 1.5; }
.responder-hint-actions { display: flex; gap: 6px; flex-shrink: 0; }
.status-pulse { animation: statusPulse 1.2s ease; border-radius: 4px; }
@keyframes statusPulse {
  0% { box-shadow: 0 0 0 0 rgba(216, 90, 48, .55); }
  70% { box-shadow: 0 0 0 8px rgba(216, 90, 48, 0); }
  100% { box-shadow: 0 0 0 0 rgba(216, 90, 48, 0); }
}
.entity-editor { display: flex; gap: 8px; margin-bottom: 12px; }
.entity-type { width: 110px; flex-shrink: 0; }
.entity-list { display: flex; flex-wrap: wrap; gap: 8px; }
.attachment-uploader { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
.attachment-uploader > span { color: #69707D; font-size: 12px; }
.attachment-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 10px; }
.attachment-card { position: relative; border: 1px solid #E8EDF3; border-radius: 6px; overflow: hidden; background: #FAFBFD; min-height: 120px; }
.attachment-card img { width: 100%; height: 92px; object-fit: cover; cursor: pointer; display: block; }
.file-box { height: 92px; display: flex; align-items: center; justify-content: center; flex-direction: column; gap: 5px; color: #69707D; font-size: 28px; }
.file-box strong { color: #5A6069; font-size: 11px; font-weight: 700; }
.attachment-name { padding: 6px 8px; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.attachment-delete { position: absolute; top: 4px; right: 4px; border: 0; border-radius: 4px; background: rgba(0,0,0,0.55); color: #fff; cursor: pointer; padding: 3px; display: flex; }
.correlation-panel { display: flex; flex-direction: column; gap: 10px; }
.correlation-summary { display: grid; grid-template-columns: repeat(3, minmax(90px, 120px)) minmax(220px, 1fr) auto; gap: 8px; align-items: stretch; }
.correlation-stat, .correlation-suggestion { border: 1px solid #E8EDF3; border-radius: 6px; padding: 8px 10px; background: #FAFBFD; min-width: 0; }
.correlation-stat span, .correlation-suggestion span { display: block; color: #69707D; font-size: 12px; margin-bottom: 4px; }
.correlation-stat strong { color: #1B1D21; font-size: 20px; }
.correlation-suggestion strong { display: block; color: #1B1D21; font-size: 13px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.correlation-reasons { display: flex; flex-wrap: wrap; gap: 6px; }
.correlation-reasons span, .related-reasons span { border: 1px solid #D3DAE6; border-radius: 4px; background: #fff; color: #5A6069; font-size: 12px; padding: 3px 6px; }
.entity-profile-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; }
.entity-profile { display: flex; align-items: center; justify-content: space-between; gap: 8px; border: 1px solid #E8EDF3; border-radius: 6px; padding: 8px 10px; background: #fff; min-width: 0; }
.entity-profile-main { min-width: 0; }
.entity-profile-main span { display: block; color: #69707D; font-size: 12px; margin-bottom: 3px; }
.entity-profile-main strong { display: block; color: #1B1D21; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.entity-profile-count { flex-shrink: 0; color: #006DE0; font-size: 12px; font-weight: 700; }
.related-list { display: flex; flex-direction: column; gap: 8px; }
.related-item { border: 1px solid #E8EDF3; border-radius: 6px; padding: 10px; cursor: pointer; background: #FAFBFD; }
.related-item:hover { border-color: #006DE0; }
.related-header { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 4px; }
.related-title { font-weight: 700; color: #1B1D21; margin-bottom: 4px; }
.related-reasons { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.json-pre { background: #F7F9FC; border: 1px solid #E8EDF3; border-radius: 6px; padding: 12px; max-height: 420px; overflow: auto; white-space: pre-wrap; word-break: break-word; font-family: Consolas, 'SF Mono', monospace; font-size: 12px; }
.detail-description { border: 1px solid #E8EDF3; border-radius: 6px; padding: 12px; background: #FAFBFD; }
.detail-grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; align-items: stretch; margin-bottom: 12px; }
.detail-dialog-body > .evidence-panel, .detail-dialog-body > .detail-description { margin-bottom: 12px; }
.detail-record-full { margin-bottom: 12px; }
.detail-description-title { font-weight: 600; font-size: 13px; color: #1B1D21; margin-bottom: 6px; }
.keyinfo-controls { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 12px; }
.keyinfo-field span { display: block; color: #69707D; font-size: 12px; margin-bottom: 5px; }
.keyinfo-field .el-select { width: 100%; }
.keyinfo-display { grid-template-columns: 1fr; }
.keyinfo-display .research-confirm { margin-top: 8px; align-self: flex-end; }
.keyinfo-display .closure-item { display: flex; flex-direction: column; }
.assign-target { display: flex; align-items: baseline; gap: 8px; margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid #E8EDF3; }
.assign-target-label, .assign-block-label { color: #69707D; font-size: 12px; flex-shrink: 0; }
.assign-target strong { color: #1B1D21; }
.assign-block { margin-bottom: 14px; }
.assign-block-label { display: block; margin-bottom: 8px; }
.assign-tags { display: flex; flex-wrap: wrap; gap: 8px; min-height: 28px; }
.assign-add { display: flex; gap: 8px; }
.assign-add .el-select { flex: 1; }
.attach-dropzone { display: flex; flex-direction: column; align-items: center; gap: 6px; border: 1px dashed #C7D0DE; border-radius: 8px; padding: 24px 16px; text-align: center; color: #8B92A0; background: #FCFDFE; cursor: pointer; transition: border-color .15s, background .15s; }
.attach-dropzone:hover, .attach-dropzone.is-dragging { border-color: #006DE0; background: #F2F8FE; }
.attach-dropzone-title { font-size: 14px; color: #5A6069; font-weight: 500; }
.attach-existing { margin-top: 14px; }
.attach-existing-title { font-size: 12px; color: #69707D; margin-bottom: 8px; }
.attach-grid { display: flex; flex-wrap: wrap; gap: 10px; }
.attach-thumb { position: relative; width: 96px; height: 72px; border: 1px solid #E8EDF3; border-radius: 6px; overflow: hidden; background: #0D1117; }
.attach-thumb .el-image { width: 100%; height: 100%; cursor: zoom-in; }
.attach-thumb .attachment-delete { top: 3px; right: 3px; }
.closure-summary { display: grid; grid-template-columns: 1fr; gap: 12px; margin-bottom: 12px; align-items: start; }
.closure-item { border: 1px solid #E8EDF3; border-radius: 6px; padding: 10px; background: #FAFBFD; min-width: 0; }
.closure-item span { display: block; color: #69707D; font-size: 12px; margin-bottom: 5px; }
.closure-item strong { display: block; color: #1B1D21; font-weight: 500; white-space: pre-wrap; word-break: break-word; min-height: 20px; }
.raw-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
.raw-header-title { font-size: 13px; font-weight: 600; color: #1B1D21; }
.empty-state { color: #8B92A0; text-align: center; padding: 20px; font-style: italic; }
.empty-detail { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #8B92A0; gap: 8px; }
.create-form { position: relative; max-height: calc(100vh - 120px); overflow: auto; padding-right: 4px; }
.dialog-header { display: flex; align-items: center; justify-content: space-between; width: 100%; }
.dialog-header-title { font-size: 16px; font-weight: 600; color: #1B1D21; }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 14px; }
.span-2 { grid-column: span 2; }
.form-actions { display: flex; justify-content: flex-end; gap: 12px; padding-top: 12px; border-top: 1px solid #E8EDF3; }
.optional-field-panel { position: absolute; top: 0; right: 8px; display: flex; align-items: center; gap: 8px; z-index: 5; }
.no-optional-hint { color: #8B92A0; font-size: 12px; }
.screenshot-section { display: flex; flex-direction: column; gap: 10px; margin: -4px 0 18px; }
.screenshot-section-title { font-size: 14px; color: #1B1D21; font-weight: 500; }
.req-star { color: #F56C6C; margin-right: 4px; }
.screenshot-field { min-width: 0; border: 1px solid #D3DAE6; border-radius: 6px; overflow: hidden; background: #FAFBFD; }
.screenshot-field-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 7px 9px; border-bottom: 1px solid #E8EDF3; color: #5A6069; font-size: 12px; font-weight: 600; }
.screenshot-paste-zone { display: flex; min-height: 112px; align-items: center; justify-content: center; flex-direction: column; gap: 7px; padding: 10px; color: #69707D; cursor: pointer; text-align: center; outline: none; }
.screenshot-paste-zone:hover, .screenshot-paste-zone:focus { background: #F0F6FC; box-shadow: inset 0 0 0 1px #006DE0; color: #006DE0; }
.screenshot-paste-zone img { width: 100%; height: 150px; object-fit: contain; display: block; }
.screenshot-section > .el-button { align-self: start; justify-self: start; }
.optional-field-label { display: flex; align-items: center; justify-content: space-between; width: 100%; gap: 8px; }
.remove-field-button { display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; border: 0; border-radius: 4px; background: transparent; color: #8B92A0; cursor: pointer; }
.remove-field-button:hover { background: #FDECEB; color: #BD271E; }

.create-attachment-field { display: flex; flex-direction: column; gap: 10px; width: 100%; }
.create-attachments { width: 100%; box-sizing: border-box; border: 2px dashed #D3DAE6; border-radius: 6px; padding: 18px; display: flex; align-items: center; justify-content: center; gap: 8px; color: #69707D; cursor: pointer; background: #FAFBFD; outline: none; transition: border-color .15s, background .15s, color .15s; }
.create-attachments:hover, .create-attachments:focus { border-color: #006DE0; background: #F0F6FC; color: #006DE0; }
.create-attachments:hover { border-color: #006DE0; color: #006DE0; }
.create-file-list { display: flex; flex-direction: column; gap: 6px; width: 100%; }
.create-file-item { display: flex; align-items: center; gap: 8px; min-width: 0; padding: 8px 10px; border: 1px solid #E1E6ED; border-radius: 6px; background: #FAFBFD; color: #445064; }
.create-file-item > .el-icon { flex-shrink: 0; color: #69707D; }
.create-file-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
.create-file-item > small { flex-shrink: 0; color: #8B92A0; font-size: 11px; }
.create-file-remove { flex-shrink: 0; color: #C0392B; }
.preview-image { max-width: 82vw; max-height: 76vh; display: block; }
:global(.optional-field-menu .el-dropdown-menu__item) { display: flex; justify-content: space-between; gap: 24px; min-width: 230px; }
:global(.optional-field-menu .el-dropdown-menu__item small) { color: #8B92A0; font-size: 11px; }
:global(.alert-detail-dialog) { display: flex; flex-direction: column; height: 100%; margin: 0 !important; border-radius: 0 !important; }
:global(.alert-detail-dialog .el-dialog__header) { flex-shrink: 0; margin: 0; padding: 12px 20px !important; }
:global(.alert-detail-dialog .el-dialog__body) { flex: 1; min-height: 0; overflow: auto; padding: 0 !important; }
@media (max-width: 1180px) {
  .stats-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .panel-actions { justify-content: flex-start; }
}
@media (max-width: 720px) {
  .stats-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .operations-header { flex-direction: column; }
  .operations-actions { width: 100%; flex-wrap: wrap; }
  .filter-keyword { width: 100%; }
  .filter-person { width: 100%; }
  .panel-actions > .el-select { flex: 1 1 130px; }
  .detail-dialog-header { align-items: flex-start; flex-direction: column; }
  .detail-navigation { width: 100%; }
  .detail-dialog-body { padding: 0 12px 16px; }
  .detail-header { align-items: flex-start; flex-direction: column; }
  .detail-grid2 { grid-template-columns: 1fr; }
  .detail-info-row { grid-template-columns: 1fr; }
  .keyinfo-controls { grid-template-columns: 1fr; }
  .closure-summary { grid-template-columns: 1fr; }
  .screenshot-section { grid-template-columns: 1fr; }
}
</style>
