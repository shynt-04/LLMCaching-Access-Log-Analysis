import { useCallback, useEffect, useRef, useState } from 'react'
import AlertDashboard from './components/AlertDashboard'
import './App.css'

const API_URL = import.meta.env.VITE_API_URL || window.location.origin

function alertKey(alert) {
  if (alert.line_number !== undefined && alert.line_number !== null) {
    return `line:${alert.line_number}`
  }
  return `${alert.timestamp || ''}|${alert.source_ip || ''}|${alert.path || ''}|${alert.merged_score}`
}

function upsertAlert(alerts, alert) {
  const key = alertKey(alert)
  const withoutCurrent = alerts.filter(existing => alertKey(existing) !== key)
  return [alert, ...withoutCurrent]
}

function chooseSession(sessions) {
  const entries = Object.entries(sessions)
  if (entries.length === 0) return null

  const processing = entries.find(([, session]) => session.status === 'processing')
  if (processing) return processing

  return entries.sort(([, a], [, b]) => (b.created_at || 0) - (a.created_at || 0))[0]
}

function App() {
  const [alerts, setAlerts] = useState([])
  const [activeSession, setActiveSession] = useState(null)
  const [sessionInfo, setSessionInfo] = useState(null)
  const [progress, setProgress] = useState(null)
  const [metrics, setMetrics] = useState(null)
  const wsRef = useRef(null)

  const connectWS = useCallback((sessionId) => {
    if (wsRef.current) {
      wsRef.current.close()
    }

    const wsUrl = API_URL.replace(/^http/, 'ws') + `/api/ws/${sessionId}`
    const ws = new WebSocket(wsUrl)

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)

      if (msg.type === 'alert') {
        setAlerts(prev => upsertAlert(prev, msg.data))
      } else if (msg.type === 'progress') {
        setProgress(msg.data)
      } else if (msg.type === 'done') {
        setMetrics(msg.data)
        setProgress(null)
        setSessionInfo(prev => prev ? {
          ...prev,
          status: 'done',
          progress: msg.data?.total_lines ?? prev.total_lines ?? prev.progress ?? 0,
          total_lines: msg.data?.total_lines ?? prev.total_lines ?? 0,
          total_alerts: msg.data?.total_alerts ?? prev.total_alerts ?? 0,
          input_files: msg.data?.input_files ?? prev.input_files,
          input_dir: msg.data?.input_dir ?? prev.input_dir,
          source: msg.data?.source ?? prev.source,
        } : prev)
      }
    }

    ws.onclose = () => {
      if (wsRef.current === ws) {
        wsRef.current = null
      }
    }

    wsRef.current = ws
  }, [])

  const loadSession = useCallback(async () => {
    try {
      const sessionsRes = await fetch(`${API_URL}/api/sessions`)
      const sessions = await sessionsRes.json()
      const selected = chooseSession(sessions)

      if (!selected) {
        setActiveSession(null)
        setSessionInfo(null)
        setAlerts([])
        setProgress(null)
        setMetrics(null)
        return
      }

      const [sessionId, info] = selected
      setActiveSession(sessionId)
      setSessionInfo(info)
      setProgress(
        info.status === 'processing'
          ? { processed: info.progress || 0, total: info.total_lines || 0 }
          : null
      )

      const alertsRes = await fetch(`${API_URL}/api/alerts/${sessionId}`)
      const alertData = await alertsRes.json()
      setAlerts(Array.isArray(alertData) ? alertData.slice().reverse() : [])

      if (info.status === 'done') {
        const metricsRes = await fetch(`${API_URL}/api/metrics/${sessionId}`)
        const metricData = await metricsRes.json()
        setMetrics(metricData.error ? null : metricData)
      } else {
        setMetrics(null)
      }

      connectWS(sessionId)
    } catch (err) {
      console.error('Failed to load dashboard session:', err)
    }
  }, [connectWS])

  const reloadInput = useCallback(async () => {
    try {
      await fetch(`${API_URL}/api/reload-input`, { method: 'POST' })
      await loadSession()
    } catch (err) {
      console.error('Failed to reload input directory:', err)
    }
  }, [loadSession])

  useEffect(() => {
    loadSession()

    return () => {
      if (wsRef.current) wsRef.current.close()
    }
  }, [loadSession])

  const processedLines = sessionInfo?.status === 'done'
    ? (metrics?.total_lines ?? sessionInfo?.total_lines ?? sessionInfo?.progress ?? 0)
    : (progress?.processed ?? sessionInfo?.progress ?? 0)
  const totalLines = metrics?.total_lines ?? progress?.total ?? sessionInfo?.total_lines ?? 0
  const statusText = sessionInfo
    ? `${sessionInfo.status || 'unknown'}: ${processedLines}/${totalLines} lines`
    : 'Waiting for input logs'

  return (
    <>
      <nav className="nav">
        <a href="/" className="nav-logo">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          DEMO APP
        </a>

        <div className="nav-links">
          <span className="nav-link active">Alert Dashboard</span>
        </div>

        <div className="nav-status">
          {activeSession && <span className="dot" />}
          <span>{statusText}</span>
        </div>
      </nav>

      <AlertDashboard
        alerts={alerts}
        activeSession={activeSession}
        apiUrl={API_URL}
        progress={progress}
        metrics={metrics}
        sessionInfo={sessionInfo}
        onReload={reloadInput}
      />
    </>
  )
}

export default App
