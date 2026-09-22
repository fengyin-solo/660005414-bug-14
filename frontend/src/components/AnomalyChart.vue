<template>
  <div class="panel">
    <h4>📈 异常分数 (3-sigma + IQR)</h4>
    <div v-if="stats && !stats.sampleSufficient" class="insufficient">
      样本不足（完整窗口 {{ stats.fullWindowCount }}/{{ stats.thresholds.minWindows }}）：统计判定不生效，分数统一为 0
    </div>
    <div ref="chart" class="chart"></div>
  </div>
</template>
<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import { useLogStore } from '../store/log'
const store = useLogStore(); const chart = ref<HTMLDivElement>(); let inst: echarts.ECharts|null=null
const stats = computed(() => store.result?.detectionStats)
function update() {
  if (!inst||!store.result) return
  const anoms = store.result.anomalies
  inst.setOption({
    backgroundColor:'transparent',grid:{left:40,right:15,top:10,bottom:25},
    xAxis:{type:'category',data:anoms.map(a=>'W'+a.windowIndex),axisLabel:{color:'#94a3b8',fontSize:9}},
    yAxis:{type:'value',axisLabel:{color:'#94a3b8'}},
    series:[
      {type:'line',data:anoms.map(a=>a.sigmaScore),name:'3-sigma',itemStyle:{color:'#f97316'},lineStyle:{width:1.5}},
      {type:'line',data:anoms.map(a=>a.iqrScore),name:'IQR',itemStyle:{color:'#a78bfa'},lineStyle:{width:1.5}}
    ],animation:false,legend:{right:0,textStyle:{color:'#94a3b8',fontSize:10}}
  })
}
onMounted(()=>{if(chart.value){inst=echarts.init(chart.value);update()}})
watch(()=>store.result,update)
onUnmounted(()=>inst?.dispose())
</script>
<style scoped>.panel{background:#1e293b;border-radius:8px;padding:12px;border:1px solid #334155}.panel h4{color:#38bdf8;font-size:13px;margin-bottom:4px}.insufficient{color:#fbbf24;font-size:11px;background:#78350f33;border-radius:4px;padding:4px 6px;margin-bottom:4px}.chart{width:100%;height:220px}</style>
