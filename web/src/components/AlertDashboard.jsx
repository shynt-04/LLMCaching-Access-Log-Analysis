import { useState, useMemo, useEffect, useCallback, useRef } from 'react'
import AlertDetail from './AlertDetail'
import AlertFilters from './AlertFilters'

/** Classify merged_score into severity level */
function getSeverity(score) {
  if (score >= 0.85) return 'critical'
  if (score >= 0.7) return 'high'
  if (score >= 0.5) return 'medium'
  return 'low'
}

/** Stable identity for an alert. Line number is unique within one analysis session. */
function alertKey(a) {
  if (a.line_number !== undefined && a.line_number !== null) {
    return `line:${a.line_number}`
  }
  return `${a.timestamp || ''}|${a.source_ip || ''}|${a.path || ''}|${a.merged_score}`
}

const EMPTY_FILTERS = {
  severities: new Set(),
  attackTypes: new Set(),
  ip: '',
  search: '',
}

/** Client-side fallback when no session or API is unavailable */
function matchesFilters(alert, filters) {
  if (filters.severities.size > 0) {
    if (!filters.severities.has(getSeverity(alert.merged_score))) return false
  }
  if (filters.attackTypes.size > 0) {
    const t = alert.analysis?.attack_type || 'unknown'
    if (!filters.attackTypes.has(t)) return false
  }
  if (filters.ip && !(alert.source_ip || '').toLowerCase().includes(filters.ip.toLowerCase())) {
    return false
  }
  if (filters.search) {
    const q = filters.search.toLowerCase()
    const haystack = [
      alert.line_number,
      alert.source_ip,
      alert.method,
      alert.path,
      alert.query_string,
      alert.status_code,
      alert.user_agent,
      alert.raw_line,
      alert.matched_rules,
      alert.attack_types,
      alert.analysis?.attack_type,
      alert.analysis?.explanation,
      alert.analysis?.cve_refs,
    ].filter(Boolean).join(' ').toLowerCase()
    if (!haystack.includes(q)) return false
  }
  return true
}

export default function AlertDashboard({ alerts, activeSession, apiUrl }) {
  const [selectedKey, setSelectedKey] = useState(null)
  const [filters, setFilters] = useState(EMPTY_FILTERS)
  const [showRawLogs, setShowRawLogs] = useState(false)

  // Server-side search state
  const [apiResults, setApiResults] = useState(null)
  const [apiLoading, setApiLoading] = useState(false)
  const [page, setPage] = useState(1)
  const [sortBy, setSortBy] = useState('line_number')
  const [sortOrder, setSortOrder] = useState('desc')
  const PAGE_SIZE = 50

  // Debounce timer ref
  const debounceRef = useRef(null)

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 }
    alerts.forEach(a => { c[getSeverity(a.merged_score)]++ })
    return c
  }, [alerts])

  const updateFilters = useCallback((nextFilters) => {
    setPage(1)
    setFilters(nextFilters)
  }, [])

  // Build query params from current filters
  const fetchAlerts = useCallback(async (currentFilters, currentPage, currentSort, currentOrder) => {
    if (!activeSession || !apiUrl) return

    const params = new URLSearchParams()

    // Severity filters
    if (currentFilters.severities.size > 0) {
      currentFilters.severities.forEach(s => params.append('severity', s))
    }

    // Attack type filters
    if (currentFilters.attackTypes.size > 0) {
      currentFilters.attackTypes.forEach(t => params.append('attack_type', t))
    }

    // IP filter
    if (currentFilters.ip) {
      params.set('ip', currentFilters.ip)
    }

    // Search query
    if (currentFilters.search) {
      params.set('search', currentFilters.search)
    }

    params.set('sort_by', currentSort)
    params.set('sort_order', currentOrder)
    params.set('page', String(currentPage))
    params.set('page_size', String(PAGE_SIZE))

    setApiLoading(true)
    try {
      const res = await fetch(`${apiUrl}/api/alerts/${activeSession}/search?${params}`)
      const data = await res.json()
      if (!data.error) {
        setApiResults({ ...data, sessionId: activeSession })
      }
    } catch (err) {
      console.error('[Search API] Error:', err)
      // Falls back to client-side filtering
      setApiResults(null)
    } finally {
      setApiLoading(false)
    }
  }, [activeSession, apiUrl, PAGE_SIZE])

  // Debounced effect: when filters/sort/page change, call API
  useEffect(() => {
    if (!activeSession || !apiUrl) {
      return
    }

    if (debounceRef.current) clearTimeout(debounceRef.current)

    debounceRef.current = setTimeout(() => {
      fetchAlerts(filters, page, sortBy, sortOrder)
    }, 300)

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [alerts.length, filters, page, sortBy, sortOrder, activeSession, apiUrl, fetchAlerts])

  // Determine displayed alerts: API results or client-side fallback
  const useApi = Boolean(apiResults && apiResults.sessionId === activeSession)
  const filtered = useApi
    ? apiResults.alerts
    : alerts.filter(a => matchesFilters(a, filters))

  const totalFiltered = useApi ? apiResults.total : filtered.length
  const totalPages = useApi ? apiResults.total_pages : 1

  const selected = selectedKey !== null
    ? filtered.find(a => alertKey(a) === selectedKey)
    : null

  const activeFilterCount =
    filters.severities.size + filters.attackTypes.size +
    (filters.ip ? 1 : 0) + (filters.search ? 1 : 0)

  return (
    <div className="page">
      {/* Severity summary + filter bar */}
      <AlertFilters
        alerts={alerts}
        filters={filters}
        onChange={updateFilters}
        counts={counts}
        showRawLogs={showRawLogs}
        onToggleRawLogs={setShowRawLogs}
      />

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
            <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>
                Alerts ({totalFiltered}{totalFiltered !== alerts.length ? ` / ${alerts.length}` : ''})
                {apiLoading && <span style={{ marginLeft: '8px', opacity: 0.6, fontSize: '0.75rem' }}>Loading...</span>}
              </span>
              {/* Sort controls */}
              {useApi && (
                <div style={{ display: 'flex', gap: '6px', alignItems: 'center', fontSize: '0.75rem' }}>
                  <select
                    id="sort-by"
                    value={sortBy}
                    onChange={e => {
                      setPage(1)
                      setSortBy(e.target.value)
                    }}
                    style={{
                      background: 'var(--surface-2)',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      color: 'var(--text-primary)',
                      padding: '2px 6px',
                      fontSize: '0.75rem',
                    }}
                  >
                    <option value="line_number">Line #</option>
                    <option value="merged_score">Score</option>
                    <option value="timestamp">Time</option>
                  </select>
                  <button
                    type="button"
                    onClick={() => {
                      setPage(1)
                      setSortOrder(o => o === 'desc' ? 'asc' : 'desc')
                    }}
                    title={sortOrder === 'desc' ? 'Descending' : 'Ascending'}
                    style={{
                      background: 'var(--surface-2)',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      color: 'var(--text-primary)',
                      padding: '2px 6px',
                      cursor: 'pointer',
                      fontSize: '0.75rem',
                    }}
                  >
                    {sortOrder === 'desc' ? 'Desc' : 'Asc'}
                  </button>
                </div>
              )}
            </div>

            {filtered.length === 0 ? (
              <div className="empty-state empty-state-filtered">
                <p>No alerts match the current filters</p>
                <p style={{ fontSize: '0.8rem' }}>
                  {activeFilterCount} active filter{activeFilterCount === 1 ? '' : 's'}.
                  Loosen them to see more results.
                </p>
              </div>
            ) : filtered.map((alert) => {
              const key = alertKey(alert)
              const attackType = alert.analysis?.attack_type || 'unknown'
              return (
                <div
                  key={key}
                  className={`alert-item alert-item-enter ${selectedKey === key ? 'selected' : ''}`}
                  onClick={() => setSelectedKey(key)}
                >
                  <div className="alert-item-top">
                    <span className={`alert-type ${attackType}`}>
                      {attackType.replace('_', ' ')}
                    </span>
                    <span className="alert-time">{alert.timestamp || '-'}</span>
                  </div>
                  <div className="alert-item-bottom">
                    <span className="alert-ip">{alert.source_ip}</span>
                    <span className="alert-path" title={alert.path}>{alert.path}</span>
                    <span className={`cache-badge ${alert.cache_hit ? 'hit' : 'miss'}`}>
                      {alert.cache_hit ? 'HIT' : 'MISS'}
                    </span>
                  </div>
                  {showRawLogs && alert.raw_line && (
                    <pre className="raw-log-preview">{alert.raw_line}</pre>
                  )}
                </div>
              )
            })}

            {/* Pagination controls */}
            {useApi && totalPages > 1 && (
              <div className="pagination-controls">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  className="pagination-btn"
                >
                  Prev
                </button>
                <span className="pagination-info">
                  Page {page} / {totalPages}
                </span>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  className="pagination-btn"
                >
                  Next
                </button>
              </div>
            )}
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
