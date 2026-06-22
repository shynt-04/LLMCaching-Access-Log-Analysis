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
<<<<<<< HEAD
    <>
      <nav className="nav">
        <a href="/" className="nav-logo">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
=======
    <div className="app-shell">
      <Sidebar />

      <div className="app-main">
        <header className="topbar">
          <a href="/" className="topbar-logo">
            <span className="logo-mark">HUST-SOICT</span>
            {/* <span className="logo-name"></span> */}
          </a>
          <div className="topbar-sep" />
          <span className="topbar-title">Alert Dashboard</span>

          <div className="topbar-right">
            <span className="topbar-status">
              {activeSession && <span className="live-dot" />}
              <span>{statusText}</span>
            </span>
            <span className="topbar-flag" title="English">
              <svg viewBox="0 0 60 30" xmlns="http://www.w3.org/2000/svg">
                <clipPath id="flag-clip"><path d="M0 0v30h60V0z" /></clipPath>
                <g clipPath="url(#flag-clip)">
                  <path d="M0 0v30h60V0z" fill="#012169" />
                  <path d="M0 0l60 30m0-30L0 30" stroke="#fff" strokeWidth="6" />
                  <path d="M0 0l60 30m0-30L0 30" stroke="#C8102E" strokeWidth="4" />
                  <path d="M30 0v30M0 15h60" stroke="#fff" strokeWidth="10" />
                  <path d="M30 0v30M0 15h60" stroke="#C8102E" strokeWidth="6" />
                </g>
              </svg>
            </span>
            <span className="topbar-user" title="User">VA</span>
          </div>
        </header>

        <AlertDashboard
          alerts={alerts}
          activeSession={activeSession}
          apiUrl={API_URL}
          progress={progress}
          metrics={metrics}
          sessionInfo={sessionInfo}
          onReload={reloadInput}
        />
      </div>
    </div>
  )
}

function Sidebar() {
  const icons = [
    // { key: 'menu', label: 'Menu', path: 'M3 6h18M3 12h18M3 18h18' },
    // { key: 'grid', label: 'Dashboard', path: 'M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z' },
    { key: 'alert', label: 'Alerts', path: 'M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0' },
    // { key: 'eye', label: 'Search', path: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z' },
    // { key: 'shield', label: 'Threats', path: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' },
    // { key: 'chart', label: 'Analytics', path: 'M3 3v18h18M7 16l4-4 3 3 5-6' },
    // { key: 'list', label: 'Reports', path: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01' },
  ]
  return (
    <nav className="sidebar">
      {icons.map((icon, i) => (
        <button
          key={icon.key}
          type="button"
          className={`sidebar-icon ${i === 2 ? 'active' : ''}`}
          title={icon.label}
          aria-label={icon.label}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
               strokeLinecap="round" strokeLinejoin="round">
            <path d={icon.path} />
>>>>>>> ba2dfd7 (Update UI)
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
