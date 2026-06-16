<script>
export default { name: 'Incident' }
</script>

<template>
  <div class="analysis-page">
    <div class="stats-grid">
      <div class="stat-card">
        <span class="stat-label">告警总数</span>
        <strong>{{ stats.total || 0 }}</strong>
      </div>
      <div class="stat-card">
        <span class="stat-label">待处理</span>
        <strong>{{ stats.pending || 0 }}</strong>
      </div>
      <div class="stat-card">
        <span class="stat-label">高危/严重</span>
        <strong>{{ criticalCount }}</strong>
      </div>
      <div class="stat-card">
        <span class="stat-label">SLA 超时</span>
        <strong>{{ stats.sla_overdue || 0 }}</strong>
      </div>
    </div>

    <div class="operations-panel kibana-panel">
      <div class="operations-header">
        <div>
          <div class="panel-title">运营概览</div>
          <div class="panel-subtitle">近 {{ operationDays }} 天告警闭环、SLA 和人员负载</div>
        </div>
        <div class="operations-actions">
          <el-select v-model="operationDays" size="small" @change="loadOperations">
            <el-option :value="7" label="近 7 天" />
            <el-option :value="30" label="近 30 天" />
            <el-option :value="90" label="近 90 天" />
          </el-select>
          <el-button size="small" @click="exportOperationsCsv">
            <el-icon><Download /></el-icon>导出报表
          </el-button>
        </div>
      </div>
      <div class="operations-grid">
        <div class="ops-metric">
          <span>新增 / 关闭</span>
          <strong>{{ operations.summary?.created || 0 }} / {{ operations.summary?.closed || 0 }}</strong>
        </div>
        <div class="ops-metric">
          <span>升级事件</span>
          <strong>{{ operations.summary?.escalated || 0 }}</strong>
        </div>
        <div class="ops-metric">
          <span>平均关闭时长</span>
          <strong>{{ operations.summary?.avg_close_hours || 0 }}h</strong>
        </div>
        <div class="ops-metric">
          <span>SLA 风险</span>
          <strong>{{ operations.summary?.overdue || 0 }} / {{ operations.summary?.warning || 0 }}</strong>
        </div>
        <div class="ops-list">
          <span>负责人负载</span>
          <div v-for="item in (operations.owner_workload || []).slice(0, 4)" :key="item.owner">
            <strong>{{ item.owner }}</strong>
            <em>{{ item.active }} 待办 / {{ item.overdue }} 超时</em>
          </div>
          <div v-if="!operations.owner_workload?.length" class="empty-inline">暂无待办</div>
        </div>
        <div class="ops-list">
          <span>来源排行</span>
          <div v-for="item in (operations.source_rank || []).slice(0, 4)" :key="item.name">
            <strong>{{ item.name }}</strong>
            <em>{{ item.count }} 条</em>
          </div>
          <div v-if="!operations.source_rank?.length" class="empty-inline">暂无数据</div>
        </div>
      </div>
    </div>

    <div class="analysis-main">
      <section class="analysis-list kibana-panel">
        <div class="panel-header">
          <div class="panel-heading">
            <div class="panel-title">告警队列</div>
            <div class="panel-subtitle">多源安全告警录入、分派、研判、关联和留痕</div>
          </div>
          <div class="queue-tabs">
            <button
              v-for="item in queueOptions"
              :key="item.value"
              type="button"
              :class="{ active: filters.queue === item.value }"
              @click="switchQueue(item.value)"
            >
              {{ item.label }}
              <strong v-if="queueCount(item.value) !== null">{{ queueCount(item.value) }}</strong>
            </button>
          </div>
          <div class="panel-actions">
            <el-input
              v-model="filters.keyword"
              size="small"
              clearable
              placeholder="搜索 IP / 主机 / Hash / 标题"
              class="filter-keyword"
              @keyup.enter="loadAlerts"
              @clear="loadAlerts"
            >
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
            <el-select v-model="filters.status" size="small" clearable placeholder="状态" @change="loadAlerts">
              <el-option v-for="item in statusOptions" :key="item.value" :label="item.label" :value="item.value" />
            </el-select>
            <el-select v-model="filters.severity" size="small" clearable placeholder="等级" @change="loadAlerts">
              <el-option v-for="item in severityOptions" :key="item.value" :label="item.label" :value="item.value" />
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
              placeholder="责任人"
              class="filter-person"
              @keyup.enter="loadAlerts"
              @clear="loadAlerts"
            />
            <el-button size="small" @click="loadAlerts">查询</el-button>
            <el-button size="small" @click="refreshAll" :loading="loading">
              <el-icon><Refresh /></el-icon>刷新
            </el-button>
            <el-button size="small" type="primary" @click="openCreate">
              <el-icon><Plus /></el-icon>新建告警
            </el-button>
          </div>
        </div>

        <div v-if="selectedAlertIds.length" class="batch-toolbar">
          <span>已选择 {{ selectedAlertIds.length }} 条</span>
          <el-input v-model="batchForm.owner" size="small" placeholder="责任人" class="batch-owner" />
          <el-button size="small" @click="batchAssign" :loading="batchLoading">批量分派</el-button>
          <el-select v-model="batchForm.severity" size="small" placeholder="等级" class="batch-select">
            <el-option v-for="item in severityOptions" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
          <el-button size="small" @click="batchChangeSeverity" :loading="batchLoading">改等级</el-button>
          <el-select v-model="batchForm.status" size="small" placeholder="状态" class="batch-select">
            <el-option v-for="item in statusOptions.filter(option => option.value !== 'closed')" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
          <el-button size="small" @click="batchChangeStatus" :loading="batchLoading">改状态</el-button>
          <el-button size="small" @click="batchAddNote" :loading="batchLoading">批量备注</el-button>
        </div>

        <el-table
          :data="alerts"
          height="100%"
          class="alert-table"
          highlight-current-row
          @row-click="selectAlert"
          @selection-change="handleSelectionChange"
        >
          <el-table-column type="selection" width="42" />
          <el-table-column prop="title" label="标题" min-width="220">
            <template #default="{ row }">
              <div class="alert-title-cell">
                <span class="severity-dot" :class="`severity-dot--${severityClass(row.severity)}`"></span>
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
          <el-table-column label="SLA" width="120">
            <template #default="{ row }">
              <el-tag size="small" :type="slaTagType(row.sla?.status)">{{ row.sla?.label || '未知' }}</el-tag>
              <div class="muted-line">{{ formatSlaRemaining(row.sla) }}</div>
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
          <el-table-column prop="owner" label="责任人" width="110" />
          <el-table-column label="更新时间" width="160">
            <template #default="{ row }">{{ formatTime(row.updated_at) }}</template>
          </el-table-column>
        </el-table>
      </section>

      <el-dialog
        v-model="detailDialogVisible"
        fullscreen
        destroy-on-close
        :show-close="false"
        class="alert-detail-dialog"
      >
        <template #header>
          <div class="detail-dialog-header">
            <div>
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
                <span class="severity-badge" :class="`severity-badge--${severityClass(selectedAlert.severity)}`">
                  {{ selectedAlert.severity || 'medium' }}
                </span>
                <span>{{ selectedAlert.title }}</span>
              </div>
              <div class="detail-meta">
                {{ selectedAlert.source_category_label || '其他 / 通用' }} · {{ selectedAlert.source_system || '未知来源' }} · {{ selectedAlert.alert_type || '未分类' }} · {{ formatTime(selectedAlert.occurred_at) }}
              </div>
            </div>
            <div class="detail-actions">
              <el-button size="small" @click="claimSelected">认领</el-button>
              <el-button size="small" @click="transferSelected">转派</el-button>
              <el-button size="small" type="warning" plain @click="openEscalateAlert">升级事件</el-button>
              <el-button size="small" type="primary" plain @click="openCloseAlert">关闭告警</el-button>
              <el-button size="small" @click="exportMarkdown"><el-icon><Download /></el-icon>导出 Markdown</el-button>
              <el-button size="small" type="danger" plain @click="removeSelected"><el-icon><Delete /></el-icon>删除</el-button>
            </div>
          </div>

          <div class="detail-grid">
            <div class="detail-card">
              <div class="card-title">流转</div>
              <el-form label-position="top" size="small">
                <el-form-item label="状态">
                  <el-select v-model="flowForm.status" @change="changeStatus">
                    <el-option v-for="item in statusOptions" :key="item.value" :label="item.label" :value="item.value" />
                  </el-select>
                </el-form-item>
                <el-form-item label="研判结论">
                  <el-select v-model="flowForm.conclusion" clearable @change="changeConclusion">
                    <el-option v-for="item in conclusionOptions" :key="item.value" :label="item.label" :value="item.value" />
                  </el-select>
                </el-form-item>
                <el-form-item label="负责人">
                  <el-input v-model="editForm.owner" placeholder="负责人" @change="saveOwner" />
                </el-form-item>
                <el-form-item label="上报人">
                  <el-input v-model="editForm.reporter" placeholder="上报人" @change="saveReporter" />
                </el-form-item>
              </el-form>
            </div>

            <div class="detail-card">
              <div class="card-title">
                标准字段
                <span class="template-label">{{ selectedAlert.source_category_label || '其他 / 通用' }}</span>
              </div>
              <div class="field-grid">
                <div
                  v-for="item in populatedFields"
                  :key="item.key"
                  :class="{ 'field-wide': item.wide }"
                >
                  <span>{{ item.label }}</span>
                  <strong :title="item.value">{{ item.value }}</strong>
                </div>
                <div v-if="!populatedFields.length" class="empty-fields">该告警未录入设备特有字段</div>
              </div>
            </div>
          </div>

          <div v-if="selectedAlert.description" class="detail-description">
            <div class="detail-description-title">告警详情</div>
            <pre class="json-pre">{{ smartFormat(selectedAlert.description) }}</pre>
          </div>

          <div v-if="selectedAlert.key_evidence || selectedAlert.handling_suggestion || selectedAlert.close_reason" class="closure-summary">
            <div class="closure-item">
              <span>关闭原因</span>
              <strong>{{ selectedAlert.close_reason || '-' }}</strong>
            </div>
            <div class="closure-item">
              <span>关键依据</span>
              <strong>{{ selectedAlert.key_evidence || '-' }}</strong>
            </div>
            <div class="closure-item">
              <span>处置建议</span>
              <strong>{{ selectedAlert.handling_suggestion || '-' }}</strong>
            </div>
          </div>

          <el-tabs v-model="activeTab" class="detail-tabs">
            <el-tab-pane label="研判记录" name="notes">
              <div class="note-editor">
                <el-input
                  v-model="noteText"
                  type="textarea"
                  :rows="3"
                  placeholder="记录研判过程、证据判断、处置建议..."
                />
                <el-button type="primary" size="small" :disabled="!noteText.trim()" @click="submitNote">添加记录</el-button>
              </div>
              <div class="timeline">
                <div v-for="note in selectedAlert.notes || []" :key="note.id" class="timeline-item">
                  <div class="timeline-time">{{ formatTime(note.created_at) }} · {{ note.author || '-' }} · {{ note.note_type }}</div>
                  <div class="timeline-content">{{ note.content }}</div>
                </div>
                <div v-if="!selectedAlert.notes?.length" class="empty-state">暂无研判记录</div>
              </div>
            </el-tab-pane>

            <el-tab-pane label="关键实体" name="entities">
              <div class="entity-editor">
                <el-select v-model="entityForm.entity_type" size="small" class="entity-type">
                  <el-option label="IP" value="ip" />
                  <el-option label="域名" value="domain" />
                  <el-option label="URL" value="url" />
                  <el-option label="Hash" value="hash" />
                  <el-option label="主机" value="host" />
                  <el-option label="账号" value="user" />
                  <el-option label="进程" value="process" />
                  <el-option label="文件路径" value="file_path" />
                </el-select>
                <el-input v-model="entityForm.value" size="small" placeholder="实体值" @keyup.enter="submitEntity" />
                <el-button size="small" type="primary" :disabled="!entityForm.value.trim()" @click="submitEntity">添加</el-button>
              </div>
              <div class="entity-list">
                <el-tag
                  v-for="entity in selectedAlert.entities || []"
                  :key="entity.id"
                  closable
                  @close="removeEntity(entity)"
                >
                  {{ entity.entity_type }} / {{ entity.role }}: {{ entity.value }}
                </el-tag>
                <div v-if="!selectedAlert.entities?.length" class="empty-state">暂无实体</div>
              </div>
            </el-tab-pane>

            <el-tab-pane label="附件与截图" name="attachments">
              <div class="attachment-uploader">
                <input ref="attachmentInputRef" hidden type="file" multiple @change="handleAttachmentPick" />
                <el-button size="small" @click="attachmentInputRef?.click()">
                  <el-icon><Upload /></el-icon>上传附件
                </el-button>
                <span>支持截图、PCAP/PCAPNG、应用日志、轮转日志和日志压缩包</span>
              </div>
              <div class="attachment-grid">
                <div v-for="att in selectedAlert.attachments || []" :key="att.id" class="attachment-card">
                  <img v-if="att.file_type === 'image'" :src="att.url" :alt="att.original_name" @click="preview(att)" />
                  <div v-else class="file-box">
                    <el-icon><Document /></el-icon>
                    <strong>{{ attachmentTypeLabel(att.file_type) }}</strong>
                  </div>
                  <div class="attachment-name" :title="att.original_name">{{ att.original_name }}</div>
                  <button class="attachment-delete" @click="removeAttachment(att)"><el-icon><Delete /></el-icon></button>
                </div>
                <div v-if="!selectedAlert.attachments?.length" class="empty-state">暂无附件</div>
              </div>
            </el-tab-pane>

            <el-tab-pane label="关联告警" name="related">
              <div class="correlation-panel">
                <div class="correlation-summary">
                  <div class="correlation-stat">
                    <span>关联告警</span>
                    <strong>{{ selectedAlert.correlation?.summary?.related_count || 0 }}</strong>
                  </div>
                  <div class="correlation-stat">
                    <span>强关联</span>
                    <strong>{{ selectedAlert.correlation?.summary?.strong_count || 0 }}</strong>
                  </div>
                  <div class="correlation-stat">
                    <span>最高分</span>
                    <strong>{{ selectedAlert.correlation?.summary?.top_score || 0 }}</strong>
                  </div>
                  <div class="correlation-suggestion">
                    <span>研判提示</span>
                    <strong>{{ selectedAlert.correlation?.summary?.suggestion || '暂未发现可用关联线索' }}</strong>
                  </div>
                  <el-button size="small" :loading="correlationLoading" @click="refreshCorrelation">
                    <el-icon><Refresh /></el-icon>刷新关联
                  </el-button>
                </div>

                <div v-if="selectedAlert.correlation?.summary?.top_reasons?.length" class="correlation-reasons">
                  <span v-for="reason in selectedAlert.correlation.summary.top_reasons" :key="reason.label">
                    {{ reason.label }} × {{ reason.count }}
                  </span>
                </div>

                <div v-if="selectedAlert.correlation?.entity_profiles?.length" class="entity-profile-list">
                  <div
                    v-for="profile in selectedAlert.correlation.entity_profiles.slice(0, 8)"
                    :key="`${profile.entity_type}:${profile.value}`"
                    class="entity-profile"
                  >
                    <div class="entity-profile-main">
                      <span>{{ profile.entity_type }} / {{ profile.role }}</span>
                      <strong :title="profile.value">{{ profile.value }}</strong>
                    </div>
                    <div class="entity-profile-count">出现 {{ profile.alert_count }} 条</div>
                  </div>
                </div>

                <div class="related-list">
                  <div v-for="item in selectedAlert.related || []" :key="item.id" class="related-item" @click="selectAlert(item)">
                    <div class="related-header">
                      <div class="related-title">{{ item.title }}</div>
                      <el-tag size="small" :type="correlationTagType(item.correlation_level)">
                        {{ item.correlation_label || '关联' }} {{ item.correlation_score || 0 }}
                      </el-tag>
                    </div>
                    <div class="muted-line">
                      {{ item.status_label || item.status }} · {{ item.conclusion_label || '未定' }} · {{ item.owner || '未分派' }} · {{ formatTime(item.updated_at) }}
                    </div>
                    <div v-if="item.correlation_reasons?.length" class="related-reasons">
                      <span v-for="reason in item.correlation_reasons.slice(0, 5)" :key="`${item.id}:${reason.key}:${reason.value}`">
                        {{ reason.label }}{{ reason.value ? `：${reason.value}` : '' }}
                      </span>
                    </div>
                  </div>
                  <div v-if="!selectedAlert.related?.length" class="empty-state">暂无关联告警</div>
                </div>
              </div>
            </el-tab-pane>

            <el-tab-pane label="分派记录" name="assignments">
              <div class="timeline">
                <div v-for="item in selectedAlert.assignments || []" :key="item.id" class="timeline-item">
                  <div class="timeline-time">{{ formatTime(item.created_at) }} · 分派人：{{ item.assigned_by || '-' }}</div>
                  <div class="timeline-content">
                    {{ item.from_owner || '未分派' }} → {{ item.to_owner || '未分派' }}
                  </div>
                </div>
                <div v-if="!selectedAlert.assignments?.length" class="empty-state">暂无分派记录</div>
              </div>
            </el-tab-pane>

            <el-tab-pane label="升级记录" name="escalations">
              <div class="timeline">
                <div v-for="item in selectedAlert.escalations || []" :key="item.id" class="timeline-item">
                  <div class="timeline-time">{{ formatTime(item.created_at) }} · 升级人：{{ item.escalated_by || '-' }} · {{ item.target_team || '-' }}</div>
                  <div class="timeline-content">
                    <strong>{{ item.severity }}</strong> · {{ item.reason }}
                    <div v-if="item.action_required">处置要求：{{ item.action_required }}</div>
                    <div v-if="item.due_at">期望完成：{{ formatTime(item.due_at) }}</div>
                  </div>
                </div>
                <div v-if="!selectedAlert.escalations?.length" class="empty-state">暂无升级记录</div>
              </div>
            </el-tab-pane>

            <el-tab-pane label="审计记录" name="audit">
              <div class="timeline">
                <div v-for="item in selectedAlert.audit || []" :key="item.id" class="timeline-item">
                  <div class="timeline-time">{{ formatTime(item.created_at) }} · {{ item.actor || '-' }} · {{ auditActionLabel(item.action) }}</div>
                  <div class="timeline-content">{{ auditSummary(item) }}</div>
                </div>
                <div v-if="!selectedAlert.audit?.length" class="empty-state">暂无审计记录</div>
              </div>
            </el-tab-pane>

            <el-tab-pane label="原始内容" name="raw">
              <div class="raw-header">
                <span class="raw-header-title">告警原始数据</span>
                <el-button-group size="small">
                  <el-button
                    :type="rawViewMode === 'formatted' ? 'primary' : 'default'"
                    @click="rawViewMode = 'formatted'"
                  >美化</el-button>
                  <el-button
                    :type="rawViewMode === 'raw' ? 'primary' : 'default'"
                    @click="rawViewMode = 'raw'"
                  >原始</el-button>
                </el-button-group>
              </div>
              <pre class="json-pre">{{ rawViewMode === 'formatted' ? smartFormat(selectedAlert.raw_content) : formatJson(selectedAlert.raw_content) }}</pre>
            </el-tab-pane>
          </el-tabs>
        </div>
      </el-dialog>
    </div>

    <el-dialog
      v-model="createDialogVisible"
      width="90vw"
      :fullscreen="createDialogFullscreen"
      :close-on-click-modal="false"
      @closed="cleanupCreateAssets"
    >
      <template #header>
        <div class="dialog-header">
          <span class="dialog-header-title">新建研判告警</span>
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
            <el-select v-model="createForm.source_category">
              <el-option v-for="item in templateOptions" :key="item.value" :label="item.label" :value="item.value" />
            </el-select>
          </el-form-item>
          <el-form-item label="告警名称" required>
            <el-input v-model="createForm.title" placeholder="例如：可疑 PowerShell 执行行为" />
          </el-form-item>
          <el-form-item label="攻击 IP">
            <el-input v-model="createForm.source_ip" placeholder="攻击来源 IP，无数据可留空" />
          </el-form-item>
          <el-form-item label="被攻击 IP">
            <el-input v-model="createForm.destination_ip" placeholder="受攻击资产 IP，无数据可留空" />
          </el-form-item>
          <el-form-item label="上报人">
            <el-input v-model="createForm.reporter" placeholder="告警提交或上报人员" />
          </el-form-item>
          <el-form-item label="研判责任人">
            <el-input v-model="createForm.owner" placeholder="负责该告警研判的人员" />
          </el-form-item>

          <el-form-item
            v-for="item in visibleOptionalFields"
            :key="item.key"
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

          <el-form-item label="告警详情" class="span-2">
            <el-input
              v-model="createForm.description"
              type="textarea"
              :rows="5"
              placeholder="粘贴安全设备中的告警详情；也可在此直接 Ctrl+V 粘贴截图"
              @paste.capture="handleDetailPaste"
            />
          </el-form-item>

          <div class="screenshot-section span-2">
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
                  <span>点击选择图片，或聚焦后 Ctrl+V 粘贴</span>
                </template>
              </div>
            </div>
            <el-button size="small" plain @click="addScreenshotSlot">
              <el-icon><Plus /></el-icon>添加截图
            </el-button>
          </div>

          <el-form-item label="其他附件" class="span-2">
            <input ref="createAttachmentInputRef" hidden type="file" multiple @change="handleCreateAttachmentPick" />
            <div class="create-attachments" @click="createAttachmentInputRef?.click()">
              <el-icon><Upload /></el-icon>
              <span>{{ createFiles.length ? `已选择 ${createFiles.length} 个文件` : '支持 PCAP/PCAPNG、应用日志、轮转日志、日志压缩包和补充图片' }}</span>
            </div>
          </el-form-item>
          <div class="form-actions span-2">
            <el-button @click="createDialogVisible = false">取消</el-button>
            <el-button type="primary" :loading="submitting" :disabled="!createForm.title.trim()" @click="submitCreate">
              创建告警
            </el-button>
          </div>
        </div>
      </el-form>
    </el-dialog>

    <el-dialog v-model="escalationDialogVisible" title="升级为安全事件" width="640px" :close-on-click-modal="false">
      <el-form label-position="top">
        <el-form-item label="接收团队" required>
          <el-input v-model="escalationForm.target_team" placeholder="例如：应急响应组 / 主机安全组 / 网络安全组" />
        </el-form-item>
        <el-form-item label="升级等级" required>
          <el-select v-model="escalationForm.severity">
            <el-option v-for="item in severityOptions" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="升级原因" required>
          <el-input v-model="escalationForm.reason" type="textarea" :rows="3" placeholder="说明为什么需要升级为事件，例如影响面、攻击链阶段、处置风险" />
        </el-form-item>
        <el-form-item label="处置要求">
          <el-input v-model="escalationForm.action_required" type="textarea" :rows="3" placeholder="隔离主机、封禁 IOC、保全日志、拉取内存、通知业务等" />
        </el-form-item>
        <el-form-item label="期望完成时间">
          <el-date-picker
            v-model="escalationForm.due_at"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            placeholder="选择时间"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="escalationDialogVisible = false">取消</el-button>
        <el-button type="warning" :loading="escalating" @click="submitEscalation">确认升级</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="closeDialogVisible" title="关闭告警" width="640px" :close-on-click-modal="false">
      <el-form label-position="top">
        <el-form-item label="研判结论" required>
          <el-select v-model="closeForm.conclusion" placeholder="请选择研判结论">
            <el-option v-for="item in conclusionOptions" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="关闭原因" required>
          <el-input v-model="closeForm.close_reason" type="textarea" :rows="3" placeholder="说明为什么可以关闭该告警" />
        </el-form-item>
        <el-form-item label="关键依据" required>
          <el-input v-model="closeForm.key_evidence" type="textarea" :rows="4" placeholder="记录支撑结论的关键证据、日志、截图或调查结果" />
        </el-form-item>
        <el-form-item label="处置建议">
          <el-input v-model="closeForm.handling_suggestion" type="textarea" :rows="3" placeholder="封禁、隔离、查杀、加固、规则优化等建议" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="closeDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="closing" @click="submitCloseAlert">确认关闭</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="previewVisible" :title="previewFile?.original_name" width="auto" align-center>
      <img v-if="previewFile" :src="previewFile.url" class="preview-image" />
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowLeft, ArrowRight, Close, Delete, Document, Download, Plus, Refresh, Search, Upload } from '@element-plus/icons-vue'
import {
  addIncidentEntity,
  addIncidentNote,
  batchIncidentAlerts,
  createIncidentAlert,
  deleteIncidentAlert,
  deleteIncidentAttachment,
  deleteIncidentEntity,
  escalateIncidentAlert,
  exportIncidentAlertMarkdown,
  exportIncidentOperationsCsv,
  getIncidentCorrelation,
  getIncidentAlert,
  getIncidentOperations,
  getIncidentStats,
  getIncidentTemplates,
  listIncidentAlerts,
  setIncidentAlertConclusion,
  setIncidentAlertStatus,
  updateIncidentAlert,
  uploadIncidentAttachment
} from '../api'

const statusOptions = [
  { value: 'new', label: '新建' },
  { value: 'pending', label: '待研判' },
  { value: 'assigned', label: '已分派' },
  { value: 'triaging', label: '初筛中' },
  { value: 'investigating', label: '研判中' },
  { value: 'waiting_info', label: '待补充信息' },
  { value: 'confirmed', label: '已确认' },
  { value: 'escalated', label: '已升级事件' },
  { value: 'closed', label: '已关闭' }
]
const severityOptions = [
  { value: 'critical', label: '严重' },
  { value: 'high', label: '高危' },
  { value: 'medium', label: '中危' },
  { value: 'low', label: '低危' },
  { value: 'info', label: '信息' }
]
const conclusionOptions = [
  { value: 'true_positive', label: '真实攻击' },
  { value: 'suspicious', label: '疑似攻击' },
  { value: 'false_positive', label: '误报' },
  { value: 'duplicate', label: '重复告警' },
  { value: 'business', label: '正常业务' },
  { value: 'unknown', label: '无法确认' }
]
const queueOptions = [
  { value: 'all', label: '全部' },
  { value: 'active', label: '处理中' },
  { value: 'my', label: '我的待办' },
  { value: 'unassigned', label: '未分派' },
  { value: 'overdue', label: '超时' },
  { value: 'escalated', label: '已升级' },
  { value: 'closed', label: '已关闭' }
]
const currentUser = 'operator'

const loading = ref(false)
const submitting = ref(false)
const closing = ref(false)
const escalating = ref(false)
const batchLoading = ref(false)
const correlationLoading = ref(false)
const alerts = ref([])
const selectedRows = ref([])
const selectedAlert = ref(null)
const detailDialogVisible = ref(false)
const stats = ref({})
const operations = ref({})
const operationDays = ref(7)
const activeTab = ref('notes')
const noteText = ref('')
const filters = ref({ keyword: '', status: '', severity: '', source_category: '', reporter: '', owner: '', queue: 'all', current_user: currentUser })
const flowForm = ref({ status: '', conclusion: '' })
const editForm = ref({ owner: '', reporter: '' })
const closeDialogVisible = ref(false)
const closeForm = ref({ conclusion: '', close_reason: '', key_evidence: '', handling_suggestion: '' })
const escalationDialogVisible = ref(false)
const escalationForm = ref({ target_team: '', severity: 'high', reason: '', action_required: '', due_at: '' })
const batchForm = ref({ owner: '', severity: '', status: '' })
const entityForm = ref({ entity_type: 'ip', value: '' })
const attachmentInputRef = ref(null)
const createAttachmentInputRef = ref(null)
const createFiles = ref([])
const createScreenshotSlots = ref([])
const selectedOptionalFieldKeys = ref([])
const createDialogVisible = ref(false)
const createDialogFullscreen = ref(false)
const previewVisible = ref(false)
const previewFile = ref(null)
const createForm = ref(newCreateForm())
const rawViewMode = ref('formatted')
const templates = ref({
  other: {
    label: '其他 / 通用',
    description: '不限定设备类型，仅填写实际存在的字段。',
    fields: []
  }
})

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
  {
    key: 'occurred_at',
    label: '告警时间',
    group: '告警信息',
    type: 'datetime'
  },
  {
    key: 'severity',
    label: '严重等级',
    group: '告警信息',
    type: 'severity'
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
    source_category: 'other',
    reporter: '',
    owner: '',
    source_system: '',
    alert_type: '',
    severity: 'medium',
    occurred_at: new Date().toISOString(),
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
  if (status === 'confirmed' || status === 'escalated') return 'success'
  if (status === 'triaging' || status === 'investigating' || status === 'waiting_info' || status === 'need_info') return 'warning'
  if (status === 'assigned') return 'primary'
  return ''
}

function slaTagType(status) {
  if (status === 'overdue') return 'danger'
  if (status === 'warning') return 'warning'
  if (status === 'done') return 'info'
  if (status === 'normal') return 'success'
  return ''
}

function correlationTagType(level) {
  if (level === 'strong') return 'danger'
  if (level === 'medium') return 'warning'
  if (level === 'weak') return 'info'
  return ''
}

function formatSlaRemaining(sla) {
  if (!sla) return '-'
  if (sla.status === 'done') return '已完成'
  if (sla.remaining_seconds === null || sla.remaining_seconds === undefined) return '-'
  const seconds = Math.abs(Number(sla.remaining_seconds || 0))
  const minutes = Math.ceil(seconds / 60)
  const hours = Math.floor(minutes / 60)
  const restMinutes = minutes % 60
  const text = hours > 0 ? `${hours}h ${restMinutes}m` : `${minutes}m`
  return sla.remaining_seconds < 0 ? `超时 ${text}` : `剩余 ${text}`
}

function queueCount(queue) {
  if (queue === 'all') return stats.value.total || 0
  if (queue === 'active') return stats.value.pending || 0
  if (queue === 'unassigned') return stats.value.unassigned || 0
  if (queue === 'overdue') return stats.value.sla_overdue || 0
  if (queue === 'escalated') return stats.value.by_status?.['已升级事件'] || 0
  if (queue === 'closed') return stats.value.by_status?.['已关闭'] || 0
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
    log_archive: '日志归档'
  }
  return labels[fileType] || String(fileType || '附件').toUpperCase()
}

function auditActionLabel(action) {
  const labels = {
    create_alert: '创建告警',
    assign_alert: '分派告警',
    update_alert: '更新告警',
    delete_alert: '删除告警',
    add_note: '添加记录',
    add_entity: '添加实体',
    delete_entity: '删除实体',
    upload_attachment: '上传附件',
    escalate_alert: '升级事件'
  }
  return labels[action] || action
}

function auditSummary(item) {
  const after = item.after_data || {}
  if (item.action === 'assign_alert') {
    return `${after.from_owner || '未分派'} → ${after.to_owner || '未分派'}，分派人：${after.assigned_by || item.actor || '-'}`
  }
  if (item.action === 'update_alert') {
    return `状态：${after.status_label || after.status || '-'}，结论：${after.conclusion_label || after.conclusion || '未定'}，责任人：${after.owner || '-'}`
  }
  if (item.action === 'escalate_alert') {
    return `接收团队：${after.target_team || '-'}，等级：${after.severity || '-'}，原因：${after.reason || '-'}`
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
  if (!file) return
  event.preventDefault()
  let slot = createScreenshotSlots.value.find(item => !item.file)
  if (!slot) {
    slot = newScreenshotSlot()
    createScreenshotSlots.value.push(slot)
  }
  setScreenshotFile(slot.id, file)
  ElMessage.success('剪贴板图片已添加为告警截图')
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

function cleanupCreateAssets() {
  for (const slot of createScreenshotSlots.value) {
    if (slot.previewUrl) URL.revokeObjectURL(slot.previewUrl)
  }
  createScreenshotSlots.value = []
  createFiles.value = []
}

async function refreshAll() {
  await Promise.all([loadTemplates(), loadStats(), loadOperations(), loadAlerts()])
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
  if (!selectedAlertIds.value.length) return
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
  } catch (e) {
    ElMessage.error('批量操作失败: ' + e.message)
  } finally {
    batchLoading.value = false
  }
}

async function batchAssign() {
  const owner = batchForm.value.owner.trim()
  if (!owner) {
    ElMessage.warning('请填写责任人')
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
  try {
    const { value } = await ElMessageBox.prompt('请输入批量备注内容', '批量备注', {
      inputType: 'textarea',
      inputPlaceholder: '记录统一处理说明',
      confirmButtonText: '确认',
      cancelButtonText: '取消'
    })
    const content = String(value || '').trim()
    if (!content) return
    await runBatch('note', { content, note_type: 'batch' }, '批量备注完成')
  } catch {}
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
      owner: selectedAlert.value.owner || '',
      reporter: selectedAlert.value.created_by || ''
    }
    detailDialogVisible.value = true
  } catch (e) {
    ElMessage.error('详情加载失败: ' + e.message)
  }
}

async function openAdjacentAlert(offset) {
  const target = alerts.value[selectedAlertIndex.value + offset]
  if (target) await selectAlert(target)
}

function openCreate() {
  cleanupCreateAssets()
  createForm.value = newCreateForm()
  createScreenshotSlots.value = [newScreenshotSlot()]
  selectedOptionalFieldKeys.value = ['occurred_at']
  createDialogVisible.value = true
}

function handleCreateAttachmentPick(e) {
  createFiles.value = Array.from(e.target.files || [])
  e.target.value = ''
}

async function submitCreate() {
  submitting.value = true
  try {
    const payload = { ...createForm.value, raw_text: createForm.value.description }
    const res = await createIncidentAlert(payload)
    if (!res.success) throw new Error(res.error || '创建失败')
    const alert = res.data
    for (const slot of createScreenshotSlots.value) {
      if (slot.file) await uploadIncidentAttachment(alert.id, slot.file)
    }
    for (const file of createFiles.value) {
      await uploadIncidentAttachment(alert.id, file)
    }
    createDialogVisible.value = false
    ElMessage.success('告警已创建')
    await refreshAll()
    await selectAlert(alert)
  } catch (e) {
    ElMessage.error('创建失败: ' + e.message)
  } finally {
    submitting.value = false
  }
}

async function changeStatus(status) {
  if (!selectedAlert.value) return
  if (status === 'closed') {
    openCloseAlert()
    flowForm.value.status = selectedAlert.value.status
    return
  }
  let reason = ''
  const res = await setIncidentAlertStatus(selectedAlert.value.id, status, reason)
  if (res.success) {
    selectedAlert.value = res.data
    ElMessage.success('状态已更新')
    await loadAlerts()
  }
}

async function changeConclusion(conclusion) {
  if (!selectedAlert.value) return
  const res = await setIncidentAlertConclusion(selectedAlert.value.id, conclusion || '')
  if (res.success) {
    selectedAlert.value = res.data
    ElMessage.success('结论已更新')
    await loadAlerts()
  }
}

async function saveOwner() {
  if (!selectedAlert.value) return
  const res = await updateIncidentAlert(selectedAlert.value.id, { owner: editForm.value.owner })
  if (res.success) {
    selectedAlert.value = res.data
    await loadAlerts()
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

async function claimSelected() {
  if (!selectedAlert.value) return
  const owner = 'operator'
  const res = await updateIncidentAlert(selectedAlert.value.id, { owner, status: 'assigned' })
  if (res.success) {
    selectedAlert.value = res.data
    editForm.value.owner = owner
    flowForm.value.status = res.data.status
    ElMessage.success('已认领')
    await loadAlerts()
  }
}

async function transferSelected() {
  if (!selectedAlert.value) return
  try {
    const { value } = await ElMessageBox.prompt('请输入新的研判责任人', '转派告警', {
      inputValue: selectedAlert.value.owner || '',
      inputPlaceholder: '责任人',
      confirmButtonText: '确认',
      cancelButtonText: '取消'
    })
    const owner = String(value || '').trim()
    if (!owner) return
    const res = await updateIncidentAlert(selectedAlert.value.id, { owner, status: 'assigned' })
    if (res.success) {
      selectedAlert.value = res.data
      editForm.value.owner = owner
      flowForm.value.status = res.data.status
      ElMessage.success('已转派')
      await loadAlerts()
    }
  } catch {}
}

function openEscalateAlert() {
  if (!selectedAlert.value) return
  escalationForm.value = {
    target_team: '',
    severity: selectedAlert.value.severity || 'high',
    reason: '',
    action_required: '',
    due_at: ''
  }
  escalationDialogVisible.value = true
}

async function submitEscalation() {
  if (!selectedAlert.value) return
  if (!escalationForm.value.target_team.trim() || !escalationForm.value.reason.trim()) {
    ElMessage.warning('请填写接收团队和升级原因')
    return
  }
  escalating.value = true
  try {
    const res = await escalateIncidentAlert(selectedAlert.value.id, escalationForm.value)
    if (!res.success) throw new Error(res.error || '升级失败')
    selectedAlert.value = res.data
    flowForm.value.status = res.data.status || 'escalated'
    escalationDialogVisible.value = false
    ElMessage.success('已升级为安全事件')
    await Promise.all([loadAlerts(), loadStats(), loadOperations()])
  } catch (e) {
    ElMessage.error('升级失败: ' + e.message)
  } finally {
    escalating.value = false
  }
}

function openCloseAlert() {
  if (!selectedAlert.value) return
  closeForm.value = {
    conclusion: selectedAlert.value.conclusion || '',
    close_reason: selectedAlert.value.close_reason || '',
    key_evidence: selectedAlert.value.key_evidence || '',
    handling_suggestion: selectedAlert.value.handling_suggestion || ''
  }
  closeDialogVisible.value = true
}

async function submitCloseAlert() {
  if (!selectedAlert.value) return
  if (!closeForm.value.conclusion || !closeForm.value.close_reason.trim() || !closeForm.value.key_evidence.trim()) {
    ElMessage.warning('请填写研判结论、关闭原因和关键依据')
    return
  }
  closing.value = true
  try {
    const res = await setIncidentAlertStatus(selectedAlert.value.id, 'closed', closeForm.value)
    if (res.success) {
      selectedAlert.value = res.data
      flowForm.value = {
        status: res.data.status || 'closed',
        conclusion: res.data.conclusion || ''
      }
      closeDialogVisible.value = false
      ElMessage.success('告警已关闭')
      await Promise.all([loadAlerts(), loadStats(), loadOperations()])
    }
  } catch (e) {
    ElMessage.error('关闭失败: ' + e.message)
  } finally {
    closing.value = false
  }
}

async function submitNote() {
  if (!selectedAlert.value || !noteText.value.trim()) return
  const res = await addIncidentNote(selectedAlert.value.id, noteText.value.trim())
  if (res.success) {
    noteText.value = ''
    await selectAlert(selectedAlert.value)
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

async function handleAttachmentPick(e) {
  const files = Array.from(e.target.files || [])
  e.target.value = ''
  if (!selectedAlert.value || files.length === 0) return
  try {
    for (const file of files) {
      await uploadIncidentAttachment(selectedAlert.value.id, file)
    }
    ElMessage.success('附件已上传')
    await selectAlert(selectedAlert.value)
  } catch (err) {
    ElMessage.error('上传失败: ' + err.message)
  }
}

async function removeAttachment(att) {
  const res = await deleteIncidentAttachment(att.id)
  if (res.success) await selectAlert(selectedAlert.value)
}

function preview(att) {
  previewFile.value = att
  previewVisible.value = true
}

async function removeSelected() {
  if (!selectedAlert.value) return
  try {
    await ElMessageBox.confirm(`确定删除告警“${selectedAlert.value.title}”？`, '确认删除', { type: 'warning' })
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

onMounted(refreshAll)
</script>

<style scoped>
.analysis-page { display: flex; flex-direction: column; gap: 12px; height: 100%; min-height: 0; }
.kibana-panel { background: #fff; border: 1px solid #D3DAE6; border-radius: 6px; overflow: hidden; }
.stats-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.stat-card { background: #fff; border: 1px solid #D3DAE6; border-radius: 6px; padding: 12px 14px; display: flex; flex-direction: column; gap: 4px; }
.stat-label { color: #69707D; font-size: 12px; }
.stat-card strong { font-size: 24px; color: #1B1D21; }
.operations-panel { display: flex; flex-direction: column; }
.operations-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; padding: 10px 12px; border-bottom: 1px solid #E8EDF3; }
.operations-actions { display: flex; align-items: center; gap: 8px; }
.operations-actions .el-select { width: 110px; }
.operations-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)) repeat(2, minmax(180px, 1.2fr)); gap: 10px; padding: 10px 12px; }
.ops-metric, .ops-list { border: 1px solid #E8EDF3; border-radius: 6px; background: #FAFBFD; padding: 8px 10px; min-width: 0; }
.ops-metric span, .ops-list > span { display: block; color: #69707D; font-size: 12px; margin-bottom: 5px; }
.ops-metric strong { display: block; color: #1B1D21; font-size: 18px; }
.ops-list div { display: flex; align-items: center; justify-content: space-between; gap: 8px; color: #1B1D21; font-size: 12px; line-height: 1.8; }
.ops-list strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ops-list em { color: #69707D; font-style: normal; flex-shrink: 0; }
.empty-inline { color: #8B92A0; justify-content: flex-start !important; }
.analysis-main { display: flex; flex: 1; min-height: 0; }
.analysis-list { display: flex; flex: 1; flex-direction: column; min-width: 0; min-height: 0; }
.panel-header { padding: 10px 12px; border-bottom: 1px solid #E8EDF3; display: flex; align-items: flex-start; flex-direction: column; gap: 10px; }
.panel-heading { flex-shrink: 0; }
.panel-title { font-weight: 700; color: #1B1D21; }
.panel-subtitle { margin-top: 3px; color: #69707D; font-size: 12px; }
.queue-tabs { display: flex; flex-wrap: wrap; gap: 6px; width: 100%; }
.queue-tabs button { border: 1px solid #D3DAE6; border-radius: 4px; background: #fff; color: #5A6069; cursor: pointer; padding: 5px 8px; display: inline-flex; align-items: center; gap: 6px; font-size: 12px; }
.queue-tabs button:hover { border-color: #006DE0; color: #006DE0; }
.queue-tabs button.active { background: #E8F1FC; border-color: #006DE0; color: #006DE0; font-weight: 700; }
.queue-tabs strong { font-size: 11px; color: inherit; }
.panel-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; justify-content: flex-end; width: 100%; }
.panel-actions > .el-select { width: 130px; }
.filter-keyword { width: 230px; }
.filter-person { width: 110px; }
.batch-toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 8px 12px; border-bottom: 1px solid #E8EDF3; background: #FAFBFD; }
.batch-toolbar > span { color: #5A6069; font-size: 12px; font-weight: 700; margin-right: 4px; }
.batch-owner { width: 130px; }
.batch-select { width: 120px; }
.alert-table { flex: 1; min-height: 0; }
.alert-title-cell { display: flex; align-items: center; gap: 8px; font-weight: 600; color: #1B1D21; }
.muted-line { color: #7A8391; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.severity-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; background: #D6A000; }
.severity-dot--critical { background: #8B0000; }
.severity-dot--high { background: #BD271E; }
.severity-dot--medium { background: #D6A000; }
.severity-dot--low, .severity-dot--info { background: #017D73; }
.detail-dialog-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; width: 100%; }
.detail-dialog-title { color: #1B1D21; font-size: 16px; font-weight: 700; }
.detail-dialog-counter { margin-top: 3px; color: #69707D; font-size: 12px; }
.detail-navigation { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.detail-dialog-body { width: min(1440px, 100%); min-height: 0; margin: 0 auto; padding: 0 20px 24px; }
.detail-header { padding: 14px 16px; border-bottom: 1px solid #E8EDF3; display: flex; justify-content: space-between; gap: 12px; }
.detail-title { display: flex; align-items: center; gap: 8px; font-size: 16px; font-weight: 700; color: #1B1D21; }
.detail-meta { margin-top: 5px; font-size: 12px; color: #69707D; }
.detail-actions { display: flex; gap: 8px; align-items: flex-start; }
.severity-badge { display: inline-flex; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; color: #fff; background: #D6A000; text-transform: uppercase; }
.severity-badge--critical { background: #8B0000; }
.severity-badge--high { background: #BD271E; }
.severity-badge--medium { background: #D6A000; }
.severity-badge--low, .severity-badge--info { background: #017D73; }
.detail-grid { display: grid; grid-template-columns: 220px 1fr; gap: 12px; padding: 12px; }
.detail-card { border: 1px solid #E8EDF3; border-radius: 6px; padding: 12px; background: #FAFBFD; }
.card-title { font-weight: 700; margin-bottom: 10px; color: #1B1D21; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.template-label { color: #006DE0; background: #E8F1FC; border-radius: 10px; padding: 2px 7px; font-size: 10px; font-weight: 600; }
.field-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 12px; }
.field-grid div { min-width: 0; }
.field-grid span { display: block; color: #69707D; font-size: 12px; }
.field-grid strong { display: block; color: #1B1D21; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.field-wide { grid-column: span 2; }
.empty-fields { grid-column: span 2; color: #8B92A0; font-weight: 400; font-size: 12px; padding: 10px 0; }
.detail-tabs { flex: 1; min-height: 0; padding: 0 12px 12px; overflow: auto; }
.note-editor { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }
.note-editor .el-button { align-self: flex-end; }
.timeline { display: flex; flex-direction: column; gap: 8px; }
.timeline-item { border-left: 3px solid #D3DAE6; padding: 6px 10px; background: #FAFBFD; }
.timeline-time { color: #69707D; font-size: 12px; margin-bottom: 4px; }
.timeline-content { color: #1B1D21; white-space: pre-wrap; }
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
.detail-description { margin-bottom: 12px; }
.detail-description-title { font-weight: 600; font-size: 13px; color: #1B1D21; margin-bottom: 6px; }
.closure-summary { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin-bottom: 12px; }
.closure-item { border: 1px solid #E8EDF3; border-radius: 6px; padding: 10px; background: #FAFBFD; min-width: 0; }
.closure-item span { display: block; color: #69707D; font-size: 12px; margin-bottom: 5px; }
.closure-item strong { display: block; color: #1B1D21; font-weight: 500; white-space: pre-wrap; word-break: break-word; }
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
.screenshot-field { min-width: 0; border: 1px solid #D3DAE6; border-radius: 6px; overflow: hidden; background: #FAFBFD; }
.screenshot-field-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 7px 9px; border-bottom: 1px solid #E8EDF3; color: #5A6069; font-size: 12px; font-weight: 600; }
.screenshot-paste-zone { display: flex; min-height: 112px; align-items: center; justify-content: center; flex-direction: column; gap: 7px; padding: 10px; color: #69707D; cursor: pointer; text-align: center; outline: none; }
.screenshot-paste-zone:hover, .screenshot-paste-zone:focus { background: #F0F6FC; box-shadow: inset 0 0 0 1px #006DE0; color: #006DE0; }
.screenshot-paste-zone img { width: 100%; height: 150px; object-fit: contain; display: block; }
.screenshot-section > .el-button { align-self: start; justify-self: start; }
.optional-field-label { display: flex; align-items: center; justify-content: space-between; width: 100%; gap: 8px; }
.remove-field-button { display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; border: 0; border-radius: 4px; background: transparent; color: #8B92A0; cursor: pointer; }
.remove-field-button:hover { background: #FDECEB; color: #BD271E; }

.create-attachments { width: 100%; border: 2px dashed #D3DAE6; border-radius: 6px; padding: 18px; display: flex; align-items: center; justify-content: center; gap: 8px; color: #69707D; cursor: pointer; background: #FAFBFD; }
.create-attachments:hover { border-color: #006DE0; color: #006DE0; }
.preview-image { max-width: 82vw; max-height: 76vh; display: block; }
:global(.optional-field-menu .el-dropdown-menu__item) { display: flex; justify-content: space-between; gap: 24px; min-width: 230px; }
:global(.optional-field-menu .el-dropdown-menu__item small) { color: #8B92A0; font-size: 11px; }
:global(.alert-detail-dialog) { display: flex; flex-direction: column; height: 100%; margin: 0 !important; border-radius: 0 !important; }
:global(.alert-detail-dialog .el-dialog__header) { flex-shrink: 0; margin: 0; padding: 12px 20px !important; }
:global(.alert-detail-dialog .el-dialog__body) { flex: 1; min-height: 0; overflow: auto; padding: 0 !important; }
@media (max-width: 1180px) {
  .stats-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .operations-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .panel-actions { justify-content: flex-start; }
}
@media (max-width: 720px) {
  .stats-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .operations-header { flex-direction: column; }
  .operations-actions { width: 100%; flex-wrap: wrap; }
  .operations-grid { grid-template-columns: 1fr; }
  .filter-keyword { width: 100%; }
  .filter-person { width: 100%; }
  .panel-actions > .el-select { flex: 1 1 130px; }
  .detail-dialog-header { align-items: flex-start; flex-direction: column; }
  .detail-navigation { width: 100%; }
  .detail-dialog-body { padding: 0 12px 16px; }
  .detail-header { align-items: flex-start; flex-direction: column; }
  .detail-grid { grid-template-columns: 1fr; }
  .closure-summary { grid-template-columns: 1fr; }
  .screenshot-section { grid-template-columns: 1fr; }
}
</style>
