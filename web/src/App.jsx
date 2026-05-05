import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { useState, useEffect, useRef, useCallback } from 'react'
import AlertDashboard from './components/AlertDashboard'
import AnalysisLab from './components/AnalysisLab'
import './App.css'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function App() {
  const [alerts, setAlerts] = useState([])
  const [sessions, setSessions] = useState({})
  const [activeSession, setActiveSession] = useState(null)
  const [progress, setProgress] = useState(null)
  const [metrics, setMetrics] = useState(null)
  const wsRef = useRef(null)

  const connectWS = useCallback((sessionId) => {
    if (wsRef.current) {
      wsRef.current.close()
    }

    const wsUrl = API_URL.replace('http', 'ws') + `/api/ws/${sessionId}`
    const ws = new WebSocket(wsUrl)

    ws.onopen = () => {
      console.log(`[WS] Connected to session ${sessionId}`)
    }

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)

      if (msg.type === 'alert') {
        setAlerts(prev => [msg.data, ...prev])
      } else if (msg.type === 'progress') {
        setProgress(msg.data)
      } else if (msg.type === 'done') {
        setMetrics(prev => ({ ...prev, [sessionId]: msg.data }))
        setProgress(null)
      }
    }

    ws.onclose = () => {
      console.log(`[WS] Disconnected from session ${sessionId}`)
    }

    wsRef.current = ws
  }, [])

  const startAnalysis = useCallback(async (file, source, useCache) => {
    setAlerts([])
    setProgress({ processed: 0, total: 0 })
    setMetrics(prev => prev)  // keep old metrics for comparison

    const formData = new FormData()
    formData.append('file', file)
    formData.append('source', source)
    formData.append('use_cache', useCache)

    try {
      const res = await fetch(`${API_URL}/api/analyze`, {
        method: 'POST',
        body: formData,
      })
      const data = await res.json()
      setActiveSession(data.session_id)
      setProgress({ processed: 0, total: data.total_lines })
      connectWS(data.session_id)
      return data
    } catch (err) {
      console.error('Failed to start analysis:', err)
      return null
    }
  }, [connectWS])

  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close()
    }
  }, [])

  return (
    <BrowserRouter>
      <nav className="nav">
        <a href="/" className="nav-logo">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          LLM Log Analyzer
        </a>

        <div className="nav-links">
          <NavLink to="/" end className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            Alert Dashboard
          </NavLink>
          <NavLink to="/lab" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            Analysis Lab
          </NavLink>
        </div>

        <div className="nav-status">
          {activeSession && <span className="dot" />}
          <span>{activeSession ? `Session: ${activeSession}` : 'No active session'}</span>
        </div>
      </nav>

      <Routes>
        <Route
          path="/"
          element={<AlertDashboard alerts={alerts} />}
        />
        <Route
          path="/lab"
          element={
            <AnalysisLab
              onStartAnalysis={startAnalysis}
              progress={progress}
              metrics={metrics}
              activeSession={activeSession}
              alerts={alerts}
            />
          }
        />
      </Routes>
    </BrowserRouter>
  )
}

export default App
