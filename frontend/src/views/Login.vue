<template>
  <div class="login-wrap">
    <div class="login-card">
      <div class="login-brand">
        <el-icon :size="22"><Warning /></el-icon>
        <span>研判分析工作台</span>
      </div>

      <!-- 登录 -->
      <template v-if="!mustChange">
        <p class="login-sub">请登录后进入工作台</p>
        <el-form @submit.prevent="onLogin">
          <el-form-item>
            <el-input v-model="form.username" placeholder="用户名" size="large" clearable
                      autocomplete="username" @keyup.enter="onLogin">
              <template #prefix><el-icon><User /></el-icon></template>
            </el-input>
          </el-form-item>
          <el-form-item>
            <el-input v-model="form.password" type="password" placeholder="口令" size="large"
                      show-password autocomplete="current-password" @keyup.enter="onLogin">
              <template #prefix><el-icon><Lock /></el-icon></template>
            </el-input>
          </el-form-item>
          <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon class="login-error" />
          <el-button type="primary" size="large" class="login-btn" :loading="loading" @click="onLogin">
            登录
          </el-button>
        </el-form>
      </template>

      <!-- 首次登录强制改密 -->
      <template v-else>
        <p class="login-sub">首次登录或口令已被重置，请设置新口令</p>
        <el-form @submit.prevent="onChangePassword">
          <el-form-item>
            <el-input v-model="pwForm.oldPassword" type="password" placeholder="当前口令" size="large"
                      show-password autocomplete="current-password">
              <template #prefix><el-icon><Lock /></el-icon></template>
            </el-input>
          </el-form-item>
          <el-form-item>
            <el-input v-model="pwForm.newPassword" type="password" placeholder="新口令（至少 12 位）" size="large"
                      show-password autocomplete="new-password">
              <template #prefix><el-icon><Key /></el-icon></template>
            </el-input>
          </el-form-item>
          <el-form-item>
            <el-input v-model="pwForm.confirm" type="password" placeholder="确认新口令" size="large"
                      show-password autocomplete="new-password" @keyup.enter="onChangePassword">
              <template #prefix><el-icon><Key /></el-icon></template>
            </el-input>
          </el-form-item>
          <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon class="login-error" />
          <el-button type="primary" size="large" class="login-btn" :loading="loading" @click="onChangePassword">
            设置新口令并进入
          </el-button>
        </el-form>
      </template>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Warning, User, Lock, Key } from '@element-plus/icons-vue'
import { auth } from '../store/auth'
import { authChangePassword } from '../api'
import { peekSessionResume, safeInternalPath } from '../utils/sessionResume'

const route = useRoute()
const router = useRouter()

const form = reactive({ username: '', password: '' })
const pwForm = reactive({ oldPassword: '', newPassword: '', confirm: '' })
const loading = ref(false)
const error = ref('')
const mustChange = ref(auth.mustChangePassword)

function proceed() {
  const resume = peekSessionResume(auth.username)
  if (resume) {
    router.replace(resume.path)
    return
  }
  const redirect = route.query.redirect
  router.replace(safeInternalPath(redirect))
}

async function onLogin() {
  if (!form.username || !form.password) {
    error.value = '请输入用户名和口令'
    return
  }
  loading.value = true
  error.value = ''
  try {
    const user = await auth.login(form.username, form.password)
    if (user.must_change_password) {
      pwForm.oldPassword = form.password
      mustChange.value = true
    } else {
      proceed()
    }
  } catch (e) {
    error.value = e.message || '登录失败'
  } finally {
    loading.value = false
  }
}

async function onChangePassword() {
  if (pwForm.newPassword.length < 12) {
    error.value = '新口令长度至少 12 位'
    return
  }
  if (pwForm.newPassword !== pwForm.confirm) {
    error.value = '两次输入的新口令不一致'
    return
  }
  loading.value = true
  error.value = ''
  try {
    await authChangePassword(pwForm.oldPassword, pwForm.newPassword)
    await auth.load(true)
    ElMessage.success('口令已更新')
    proceed()
  } catch (e) {
    error.value = e.message || '修改口令失败'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-wrap {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #eef3fb 0%, #f7f9fc 100%);
}
.login-card {
  width: 360px;
  background: #fff;
  border: 1px solid var(--border, #d3dae6);
  border-radius: 10px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
  padding: 32px 28px;
}
.login-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 18px;
  font-weight: 700;
  color: var(--primary, #006DE0);
  margin-bottom: 6px;
}
.login-sub {
  color: var(--text-secondary, #5A6069);
  font-size: 13px;
  margin-bottom: 20px;
}
.login-error {
  margin-bottom: 12px;
}
.login-btn {
  width: 100%;
  margin-top: 4px;
}
</style>
