import { createRouter, createWebHistory } from 'vue-router'
import Incident from '../views/Incident.vue'
import Login from '../views/Login.vue'
import { auth } from '../store/auth'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: { public: true }
  },
  {
    path: '/',
    redirect: '/incident'
  },
  {
    path: '/incident',
    name: 'Incident',
    component: Incident
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 路由守卫：首次进入探测会话；未登录访问受保护路由 -> 跳登录页
router.beforeEach(async (to) => {
  if (!auth.loaded) await auth.load()

  if (to.meta.public) {
    // 已登录用户访问登录页 -> 回工作台
    if (to.name === 'Login' && auth.isAuthenticated) return { path: '/incident' }
    return true
  }

  if (!auth.isAuthenticated) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
  return true
})

export default router
