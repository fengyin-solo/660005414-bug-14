import { defineStore } from 'pinia'
import { ref, watch } from 'vue'
import axios from 'axios'
import type { AnalysisResult, AlertRule } from '@/types'

// 重新进入页面时恢复上一次结果：窗口列表与分数必须与离开时一致
const STORAGE_KEY = 'log-analysis-result-v2'

function loadPersisted(): AnalysisResult | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) as AnalysisResult : null
  } catch {
    return null
  }
}

export const useLogStore = defineStore('log', () => {
  const result = ref<AnalysisResult | null>(loadPersisted())
  const loading = ref(false)
  const searchQuery = ref('')
  const logType = ref('nginx')
  const rules = ref<AlertRule[]>([
    { id:1, name:'高频ERROR', type:'level', threshold:5, enabled:true },
    { id:2, name:'异常流量', type:'count', threshold:200, enabled:false },
    { id:3, name:'关键词命中', type:'keyword', threshold:0, enabled:true }
  ])

  // 每次分析结果落盘，刷新/重新进入页面拿到的是同一份窗口与分数
  watch(result, (val) => {
    try {
      if (val) localStorage.setItem(STORAGE_KEY, JSON.stringify(val))
      else localStorage.removeItem(STORAGE_KEY)
    } catch { /* 存储失败（如容量超限）不影响本次分析 */ }
  }, { deep: true })

  async function generate() {
    loading.value=true
    try { const {data} = await axios.post('/api/generate',{type:logType.value,count:1000}) ; result.value=data }
    finally { loading.value=false }
  }

  async function detect() {
    if (!result.value) return
    loading.value=true
    try {
      // 始终把全量日志发回后端：窗口由后端按同一份数据切分，
      // 保证返回的窗口序号与 windows/anomalies 列表一一对应
      const {data} = await axios.post('/api/detect',{
        logs:result.value.logs,
        rules:rules.value.filter(r=>r.enabled),
        query:searchQuery.value
      })
      result.value=data
    }
    finally { loading.value=false }
  }

  return { result, loading, searchQuery, logType, rules, generate, detect }
})
