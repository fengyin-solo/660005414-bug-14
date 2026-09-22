export interface LogEntry { id: number; timestamp: string; level: string; source: string; message: string; raw: string }
export interface TimeWindow { index: number; start: number; end: number; count: number; partial: boolean; firstTimestamp: string; levels: Record<string,number>; sources: Record<string,number> }
export interface AnomalyScore { windowIndex: number; sigmaScore: number; iqrScore: number; isAnomaly: boolean; partial: boolean; timestamp: string }
export interface AlertRule { id: number; name: string; type: string; threshold: number; enabled: boolean }
export interface Alert { id: number; ruleName: string; severity: string; message: string; timestamp: string }
export interface DetectionStats {
  windowCount: number
  fullWindowCount: number
  sampleSufficient: boolean
  mean: number
  std: number
  q1: number
  q3: number
  thresholds: { sigma: number; iqr: number; sigmaCritical: number; iqrCritical: number; minWindows: number; windowSize: number }
}
export interface AnalysisResult {
  logs: LogEntry[]
  matchedLogs: LogEntry[]
  windows: TimeWindow[]
  anomalies: AnomalyScore[]
  alerts: Alert[]
  totalLogs: number
  detectionStats?: DetectionStats
}
