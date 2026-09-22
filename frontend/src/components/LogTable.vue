<template>
  <div class="panel" style="height:100%">
    <h4>
      📋 日志流 ({{ store.result?.totalLogs || 0 }} 条)
      <span v-if="store.searchQuery && store.result" class="match-hint">
        匹配 {{ displayLogs.length }} 条（最多展示200条，窗口统计仍基于全部日志）
      </span>
    </h4>
    <div class="table-wrap">
      <el-table :data="displayLogs" size="small" max-height="400" stripe>
        <el-table-column prop="id" label="#" width="50"/>
        <el-table-column prop="timestamp" label="时间" width="150"/>
        <el-table-column prop="level" label="级别" width="70">
          <template #default="{row}"><el-tag size="small" :type="row.level==='ERROR'||row.level==='error'?'danger':row.level==='WARN'||row.level==='warn'?'warning':'info'">{{ row.level }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="source" label="来源" width="120"/>
        <el-table-column prop="message" label="消息" show-overflow-tooltip/>
      </el-table>
    </div>
  </div>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { useLogStore } from '../store/log'
const store = useLogStore()
// 有搜索词时展示后端返回的匹配结果（matchedLogs），但切窗始终用全量 logs，互不影响
const displayLogs = computed(() => {
  const r = store.result
  if (!r) return []
  return store.searchQuery ? (r.matchedLogs || []) : r.logs
})
</script>
<style scoped>.panel{background:#1e293b;border-radius:8px;padding:12px;height:100%;border:1px solid #334155}.panel h4{color:#38bdf8;font-size:13px;margin-bottom:8px}.match-hint{color:#fbbf24;font-size:11px;font-weight:400;margin-left:8px}.table-wrap{height:calc(100% - 30px);overflow:auto}</style>
