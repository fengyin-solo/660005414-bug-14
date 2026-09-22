import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import type { AnalysisResult, AlertRule } from '@/types'

const STORAGE_KEY = 'log-anomaly-analysis-v2'

function loadResult(): AnalysisResult | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) as AnalysisResult : null
  } catch {
    return null
  }
}

function saveResult(result: AnalysisResult | null) {
  try {
    if (result) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(result))
    } else {
      localStorage.removeItem(STORAGE_KEY)
    }
  } catch {
    // localStorage can be unavailable or full; in-memory state still works.
  }
}

export const useLogStore = defineStore('log', () => {
  const result = ref<AnalysisResult | null>(loadResult())
  const loading = ref(false)
  const searchQuery = ref('')
  const logType = ref('nginx')
  const rules = ref<AlertRule[]>([
    { id: 1, name: '高频ERROR', type: 'level', threshold: 5, enabled: true },
    { id: 2, name: '异常流量', type: 'count', threshold: 18, enabled: false },
    { id: 3, name: '关键词命中', type: 'keyword', threshold: 0, enabled: true }
  ])

  async function generate() {
    loading.value = true
    try {
      const { data } = await axios.post('/api/generate', { type: logType.value, count: 1000 })
      result.value = data
      saveResult(data)
    } finally {
      loading.value = false
    }
  }

  async function detect() {
    if (!result.value) return
    loading.value = true
    try {
      const payload = result.value.allLogs ?? result.value.logs
      const { data } = await axios.post('/api/detect', {
        logs: payload,
        rules: rules.value.filter(rule => rule.enabled),
        query: searchQuery.value
      })
      result.value = data
      saveResult(data)
    } finally {
      loading.value = false
    }
  }

  return { result, loading, searchQuery, logType, rules, generate, detect }
})
