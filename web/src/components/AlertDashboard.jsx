import { useState, useMemo, useEffect, useCallback, useRef } from 'react'
import AlertDetail from './AlertDetail'
import AlertFilters from './AlertFilters'

const VALID_SEVERITIES = new Set(['low', 'medium', 'high', 'critical'])
const SEVERITY_ALIASES = {
  crit: 'critical',
  med: 'medium',
  warn: 'medium',
  warning: 'medium',
  info: 'low',
  informational: 'low',
}

function normalizeSeverity(value) {
  const text = String(value || '').trim().toLowerCase()
  const normalized = SEVERITY_ALIASES[text] || text
  return VALID_SEVERITIES.has(normalized) ? normalized : null
}

/** Fallback only for older alerts that do not include analysis.severity. */
function scoreFallbackSeverity(score) {
  if (score >= 0.85) return 'critical'
  if (score >= 0.7) return 'high'
  if (score >= 0.5) return 'medium'
  return 'low'
}

function getSeverity(alert) {
  return normalizeSeverity(alert?.severity)
    || normalizeSeverity(alert?.analysis?.severity)
    || scoreFallbackSeverity(alert?.merged_score || 0)
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
    if (!filters.severities.has(getSeverity(alert))) return false
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

const SEVERITY_STATS = [
  { key: 'critical', label: 'Critical', dot: 'dot-critical' },
  { key: 'high', label: 'High', dot: 'dot-high' },
  { key: 'medium', label: 'Medium', dot: 'dot-medium' },
  { key: 'low', label: 'Low', dot: 'dot-low' },
  { key: 'noimpact', label: 'No impact', dot: 'dot-noimpact' },
]

function ruleIdText(alert) {
  const rules = alert.matched_rules
  if (Array.isArray(rules) && rules.length > 0) {
    return rules.map(r => (typeof r === 'string' ? r : r.name || JSON.stringify(r))).join(', ')
  }
  return '—'
}

export default function AlertDashboard({
  alerts,
  activeSession,
  apiUrl,
  progress,
  metrics,
  sessionInfo,
  onReload,
}) {
  const [selectedKey, setSelectedKey] = useState(null)
  const [filters, setFilters] = useState(EMPTY_FILTERS)
  const [showRawLogs, setShowRawLogs] = useState(false)
  const [showStats, setShowStats] = useState(true)
  const [checkedRows, setCheckedRows] = useState(() => new Set())

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
    const c = { critical: 0, high: 0, medium: 0, low: 0, noimpact: 0 }
    alerts.forEach(a => { c[getSeverity(a)]++ })
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

  // ── Severity stat click → toggle severity filter ──────────
  const toggleSeverity = useCallback((sev) => {
    if (sev === 'noimpact') return // no backend severity for "no impact"
    const next = new Set(filters.severities)
    next.has(sev) ? next.delete(sev) : next.add(sev)
    updateFilters({ ...filters, severities: next })
  }, [filters, updateFilters])

  const setSearch = useCallback((search) => {
    updateFilters({ ...filters, search })
  }, [filters, updateFilters])

  // ── Header sort toggle (server-side sort) ─────────────────
  const onSort = useCallback((field) => {
    setPage(1)
    if (sortBy === field) {
      setSortOrder(o => (o === 'desc' ? 'asc' : 'desc'))
    } else {
      setSortBy(field)
      setSortOrder('desc')
    }
  }, [sortBy])

  const sortArrow = (field) => (sortBy === field ? (sortOrder === 'desc' ? ' ▼' : ' ▲') : '')

  // ── Row checkbox selection ────────────────────────────────
  const toggleChecked = useCallback((key) => {
    setCheckedRows(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }, [])

  // ── Export current filtered page as JSON ──────────────────
  const exportData = useCallback(() => {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `alerts_${activeSession || 'session'}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }, [filtered, activeSession])

  // ── Date range string from current rows ───────────────────
  const dateRange = useMemo(() => {
    if (filtered.length === 0) return ''
    const times = filtered.map(a => a.timestamp).filter(Boolean)
    if (times.length === 0) return ''
    const first = times[times.length - 1]
    const last = times[0]
    return first === last ? first : `${first} – ${last}`
  }, [filtered])

  const statusCount = totalFiltered

  return (
    <div className="content">
      {/* ── Source / session strip ─────────────────────────── */}
      <div className="source-strip">
        <div className="source-strip-meta">
          <span className="label">Input</span>
          <span className="source-tag">{sessionInfo?.input_dir || 'input'}</span>
          <span className="source-tag">{sessionInfo?.source || 'auto'}</span>
          <span className="source-tag">{sessionInfo?.use_cache ? 'cache on' : 'cache off'}</span>
          {sessionInfo?.input_files?.length > 0 && (
            <span className="source-files">{sessionInfo.input_files.join(', ')}</span>
          )}
        </div>

        <div className="source-strip-actions">
          {progress && (
            <div className="mini-progress">
              <div className="progress-bar-outer">
                <div
                  className="progress-bar-inner"
                  style={{
                    width: progress.total > 0
                      ? `${(progress.processed / progress.total) * 100}%`
                      : '0%',
                  }}
                />
              </div>
              <span>{progress.processed}/{progress.total}</span>
            </div>
          )}
          {metrics && (
            <div className="mini-metrics">
              <span>{metrics.total_alerts} alerts</span>
              <span>{metrics.total_llm_calls} LLM</span>
              <span>{(metrics.cache_hit_rate * 100).toFixed(1)}% cache</span>
            </div>
          )}
          <button type="button" className="btn btn-secondary" onClick={onReload}>
            Reload Input
          </button>
        </div>
      </div>

      {/* ── Toolbar row ────────────────────────────────────── */}
      <div className="toolbar">
        <button type="button" className="btn btn-secondary" disabled>
          Save query
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 9l6 6 6-6" /></svg>
        </button>

        <div className="search-box">
          <span className="search-fx">fx</span>
          <input
            type="text"
            value={filters.search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by queries, IP, path, raw log..."
            aria-label="Search alerts"
          />
        </div>

        <button type="button" className="btn btn-secondary" disabled>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="4" width="18" height="18" rx="2" /><path d="M16 2v4M8 2v4M3 10h18" />
          </svg>
          Last 24 hours
        </button>

        <button type="button" className="btn btn-dark btn-icon" aria-label="Search">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" />
          </svg>
        </button>

        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => setShowStats(s => !s)}
        >
          {showStats ? 'Hide statistics' : 'Show statistics'}
        </button>
      </div>

      {/* ── Statistics bar ─────────────────────────────────── */}
      {showStats && (
        <div className="stats-bar">
          <div className="stats-section">
            <span className="stats-section-label">Severity</span>
            <div className="stats-items">
              {SEVERITY_STATS.map(s => {
                const active = filters.severities.has(s.key)
                const dim = filters.severities.size > 0 && !active && s.key !== 'noimpact'
                return (
                  <button
                    key={s.key}
                    type="button"
                    className={`stat-item ${s.key === 'noimpact' ? 'static' : ''} ${active ? 'active' : ''} ${dim ? 'dim' : ''}`}
                    onClick={() => toggleSeverity(s.key)}
                    title={s.key === 'noimpact' ? s.label : `Filter by ${s.label}`}
                  >
                    <span className="stat-label">
                      <span className={`stat-dot ${s.dot}`} />
                      {s.label}
                    </span>
                    <span className="stat-number">{counts[s.key] ?? 0}</span>
                  </button>
                )
              })}
            </div>
          </div>

          <div className="stats-section with-divider">
            <span className="stats-section-label">Status</span>
            <div className="stats-items">
              <div className="stat-item static">
                <span className="stat-label"><span className="stat-dot dot-new" />New</span>
                <span className="stat-number">{statusCount}</span>
              </div>
              <div className="stat-item static">
                <span className="stat-label"><span className="stat-dot dot-inprogress" />In progress</span>
                <span className="stat-number">0</span>
              </div>
              <div className="stat-item static">
                <span className="stat-label"><span className="stat-dot dot-falsepos" />False positive</span>
                <span className="stat-number">0</span>
              </div>
              <div className="stat-item static">
                <span className="stat-label"><span className="stat-dot dot-closed" />Closed</span>
                <span className="stat-number">0</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Secondary filters (attack type / ip / raw / clear) ─ */}
      <AlertFilters
        alerts={alerts}
        filters={filters}
        onChange={updateFilters}
        showRawLogs={showRawLogs}
        onToggleRawLogs={setShowRawLogs}
      />

      {alerts.length === 0 ? (
        <div className="table-wrap">
          <div className="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <p>No alerts yet</p>
            <p className="sub">
              The app analyzes log files from the configured input directory when the backend starts.
            </p>
          </div>
        </div>
      ) : (
        <>
          {/* ── Table controls row ─────────────────────────── */}
          <div className="table-controls">
            <span className="table-result-count">
              Showing {filtered.length} of {totalFiltered.toLocaleString()} result(s)
              {apiLoading && <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>Loading…</span>}
            </span>
            {dateRange && <span className="table-date-range">{dateRange}</span>}

            <div className="table-controls-actions">
              <button type="button" className="btn btn-dark" onClick={exportData}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />
                </svg>
                Export data
              </button>
              <button type="button" className="btn btn-secondary" disabled>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
                </svg>
                Group rows by…
              </button>
              <button type="button" className="btn btn-secondary" disabled>•••</button>
            </div>
          </div>

          {/* ── Alert table ────────────────────────────────── */}
          <div className="table-wrap">
            {filtered.length === 0 ? (
              <div className="empty-state">
                <p>No alerts match the current filters</p>
                <p className="sub">
                  {activeFilterCount} active filter{activeFilterCount === 1 ? '' : 's'}. Loosen them to see more results.
                </p>
              </div>
            ) : (
              <table className="alert-table">
                <thead>
                  <tr>
                    <th className="col-check" />
                    <th
                      className="col-sev sortable"
                      onClick={() => onSort('merged_score')}
                    >
                      Severity<span className="sort-arrow">{sortArrow('merged_score')}</span>
                    </th>
                    <th className="col-status">Status</th>
                    <th
                      className="col-time sortable"
                      onClick={() => onSort('timestamp')}
                    >
                      Timestamp create<span className="sort-arrow">{sortArrow('timestamp')}</span>
                    </th>
                    <th className="col-host">Host name</th>
                    <th className="col-scenario">Attack Type</th>
                    <th className="col-object">Object</th>
                    <th className="col-rule">Rule id</th>
                    <th className="col-desc">Description</th>
                    <th className="col-action">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((alert) => {
                    const key = alertKey(alert)
                    const sev = getSeverity(alert)
                    const attackType = (alert.analysis?.attack_type || 'unknown').replace(/_/g, ' ')
                    const checked = checkedRows.has(key)
                    return (
                      <tr
                        key={key}
                        className={`${checked ? 'selected' : ''} ${selectedKey === key ? 'row-open' : ''}`}
                        onClick={() => setSelectedKey(key)}
                      >
                        <td className="col-check" onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => toggleChecked(key)}
                            aria-label="Select alert"
                          />
                        </td>
                        <td className="col-sev">
                          <span className={`badge-severity badge-${sev}`}>{sev}</span>
                        </td>
                        <td className="col-status">
                          <span className="status-cell"><span className="stat-dot dot-new" />New</span>
                        </td>
                        <td className="col-time mono">{alert.timestamp || '—'}</td>
                        <td className="col-host mono">{alert.source_ip || '—'}</td>
                        <td className="col-scenario" style={{ textTransform: 'capitalize' }}>{attackType}</td>
                        <td className="col-object mono">
                          <span className="cell-ellipsis" title={alert.path}>{alert.path || '—'}</span>
                        </td>
                        <td className="col-rule">
                          <span className="cell-ellipsis mono" title={ruleIdText(alert)}>{ruleIdText(alert)}</span>
                        </td>
                        <td className="col-desc">
                          <span className="cell-ellipsis" title={alert.analysis?.explanation || ''}>
                            {alert.analysis?.explanation || '—'}
                          </span>
                        </td>
                        <td className="col-action">
                          <span className={`cache-badge ${alert.cache_hit ? 'hit' : 'miss'}`}>
                            {alert.cache_hit ? 'HIT' : 'MISS'}
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}

            {/* Pagination */}
            {useApi && totalPages > 1 && (
              <div className="pagination">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  className="pagination-btn"
                >
                  Prev
                </button>
                <span className="pagination-info">Page {page} / {totalPages}</span>
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
        </>
      )}

      {/* ── Detail drawer ──────────────────────────────────── */}
      {selected && <div className="drawer-backdrop" onClick={() => setSelectedKey(null)} />}
      <aside className={`drawer ${selected ? 'open' : ''}`}>
        {selected && (
          <AlertDetail
            alert={selected}
            showRawLogs={showRawLogs}
            onClose={() => setSelectedKey(null)}
          />
        )}
      </aside>
    </div>
  )
}
