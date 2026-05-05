import { useState, useMemo } from 'react'
import AlertDetail from './AlertDetail'

/** Classify merged_score into severity level */
function getSeverity(score) {
  if (score >= 0.85) return 'critical'
  if (score >= 0.7) return 'high'
  if (score >= 0.5) return 'medium'
  return 'low'
}

export default function AlertDashboard({ alerts }) {
  const [selectedIdx, setSelectedIdx] = useState(null)

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 }
    alerts.forEach(a => { c[getSeverity(a.merged_score)]++ })
    return c
  }, [alerts])

  const selected = selectedIdx !== null ? alerts[selectedIdx] : null

  return (
    <div className="page">
      {/* Severity summary bar */}
      <div className="severity-bar">
        <div className="severity-badge critical">
          <span>CRITICAL</span>
          <span className="severity-count">{counts.critical}</span>
        </div>
        <div className="severity-badge high">
          <span>HIGH</span>
          <span className="severity-count">{counts.high}</span>
        </div>
        <div className="severity-badge medium">
          <span>MEDIUM</span>
          <span className="severity-count">{counts.medium}</span>
        </div>
        <div className="severity-badge low">
          <span>LOW</span>
          <span className="severity-count">{counts.low}</span>
        </div>
      </div>

      {alerts.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <p>No alerts yet</p>
            <p style={{ fontSize: '0.8rem' }}>
              Upload a log file in the Analysis Lab to start detecting threats
            </p>
          </div>
        </div>
      ) : (
        <div className="dashboard-grid">
          {/* Alert list (left) */}
          <div className="card alert-list">
            <div className="card-header">
              Alerts ({alerts.length})
            </div>
            {alerts.map((alert, idx) => {
              const severity = getSeverity(alert.merged_score)
              const attackType = alert.analysis?.attack_type || 'unknown'
              return (
                <div
                  key={idx}
                  className={`alert-item alert-item-enter ${selectedIdx === idx ? 'selected' : ''}`}
                  onClick={() => setSelectedIdx(idx)}
                >
                  <div className="alert-item-top">
                    <span className={`alert-type ${attackType}`}>
                      {attackType.replace('_', ' ')}
                    </span>
                    <span className="alert-time">{alert.timestamp || '—'}</span>
                  </div>
                  <div className="alert-item-bottom">
                    <span className="alert-ip">{alert.source_ip}</span>
                    <span className="alert-path" title={alert.path}>{alert.path}</span>
                    <span className={`cache-badge ${alert.cache_hit ? 'hit' : 'miss'}`}>
                      {alert.cache_hit ? '⚡ HIT' : '🔄 MISS'}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Alert detail (right) */}
          <div className="card">
            {selected ? (
              <AlertDetail alert={selected} />
            ) : (
              <div className="detail-empty">
                Click an alert to view details
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
