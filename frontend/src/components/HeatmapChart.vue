<template>
  <div class="panel"><h4>🔥 日志级别热力图</h4><div ref="chart" class="chart"></div></div>
</template>
<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import { useLogStore } from '../store/log'
const store = useLogStore(); const chart = ref<HTMLDivElement>(); let inst: echarts.ECharts|null=null
function update() {
  if (!inst||!store.result) return
  const ws = store.result.windows; const levels = ['INFO','WARN','ERROR','DEBUG']
  const data: [number,number,number][] = []
  ws.forEach((w) => { levels.forEach((lv,j) => { data.push([w.windowIndex,j,w.levels[lv]||0]) }) })
  inst.setOption({
    backgroundColor:'transparent',grid:{left:60,right:15,top:5,bottom:25},
    xAxis:{type:'category',data:ws.map(w=>'W'+w.windowIndex),axisLabel:{color:'#94a3b8',fontSize:8}},
    yAxis:{type:'category',data:levels,axisLabel:{color:'#94a3b8',fontSize:9}},
    visualMap:{min:0,max:Math.max(...data.map(d=>d[2]),1),inRange:{color:['#1e293b','#fef08a','#ef4444']},calculable:false,show:false},
    series:[{type:'heatmap',data,label:{show:true,fontSize:8,color:'#94a3b8'}}],animation:false
  })
}
onMounted(()=>{if(chart.value){inst=echarts.init(chart.value);update()}})
watch(()=>store.result,update)
onUnmounted(()=>inst?.dispose())
</script>
<style scoped>.panel{background:#1e293b;border-radius:8px;padding:12px;border:1px solid #334155}.panel h4{color:#38bdf8;font-size:13px;margin-bottom:4px}.chart{width:100%;height:200px}</style>