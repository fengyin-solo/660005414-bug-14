export interface LogEntry { id: number; timestamp: string; level: string; source: string; message: string; raw: string }
export interface TimeWindow {
  index: number
  windowIndex: number
  start: number
  end: number
  count: number
  capacity: number
  coverage: number
  errorCount: number
  errorRate: number
  errorCoverage: number
  levels: Record<string, number>
  sources: Record<string, number>
  timestamp: string
}
export interface AnomalyScore {
  windowIndex: number
  sigmaScore: number
  iqrScore: number
  isAnomaly: boolean
  status: 'normal' | 'anomaly' | 'insufficient_samples'
  timestamp: string
}
export interface AlertRule { id: number; name: string; type: string; threshold: number; enabled: boolean }
export interface Alert { id: number; ruleName: string; severity: string; message: string; timestamp: string }
export interface AnalysisResult {
  logs: LogEntry[]
  allLogs: LogEntry[]
  windows: TimeWindow[]
  anomalies: AnomalyScore[]
  alerts: Alert[]
  totalLogs: number
  metadata?: {
    windowSize: number
    minWindows: number
    sigmaThreshold: number
    iqrThreshold: number
    windowCount: number
    reliable: boolean
    defaultThresholds: Record<string, number>
  }
}
