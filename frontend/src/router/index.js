import { createRouter, createWebHistory } from 'vue-router'
import Incident from '../views/Incident.vue'

const routes = [
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

export default router
