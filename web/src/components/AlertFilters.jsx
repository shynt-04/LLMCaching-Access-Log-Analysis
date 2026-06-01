import { useMemo } from 'react'

const SEVERITIES = ['critical', 'high', 'medium', 'low']

export default function AlertFilters({
  alerts,
  filters,
  onChange,
  counts,
  showRawLogs,
  onToggleRawLogs,
}) {
  const attackTypes = useMemo(() => {
    const set = new Set()
    alerts.forEach(a => set.add(a.analysis?.attack_type || 'unknown'))
    return Array.from(set).sort()
  }, [alerts])

  const toggleSeverity = (sev) => {
    const next = new Set(filters.severities)
    next.has(sev) ? next.delete(sev) : next.add(sev)
    onChange({ ...filters, severities: next })
  }

  const toggleAttackType = (type) => {
    const next = new Set(filters.attackTypes)
    next.has(type) ? next.delete(type) : next.add(type)
    onChange({ ...filters, attackTypes: next })
  }

  const setIp = (ip) => onChange({ ...filters, ip })
  const setSearch = (search) => onChange({ ...filters, search })

  const activeCount =
    filters.severities.size +
    filters.attackTypes.size +
    (filters.ip ? 1 : 0) +
    (filters.search ? 1 : 0)

  const clearAll = () => onChange({
    severities: new Set(),
    attackTypes: new Set(),
    ip: '',
    search: '',
  })

  return (
    <div className="filter-bar">
      {/* Severity badges (clickable, double as filter toggles) */}
      <div className="filter-row severity-bar">
        {SEVERITIES.map(sev => {
          const active = filters.severities.has(sev)
          const dim = filters.severities.size > 0 && !active
          return (
            <button
              key={sev}
              type="button"
              className={`severity-badge ${sev} ${active ? 'active' : ''} ${dim ? 'dim' : ''}`}
              onClick={() => toggleSeverity(sev)}
              title={`Filter by ${sev}`}
            >
              <span>{sev.toUpperCase()}</span>
              <span className="severity-count">{counts[sev]}</span>
            </button>
          )
        })}
      </div>

      {/* Filter controls row */}
      <div className="filter-row filter-controls">
        <div className="filter-group">
          <label>Attack Type</label>
          <div className="filter-chips">
            {attackTypes.length === 0 && (
              <span className="filter-chip-empty">none yet</span>
            )}
            {attackTypes.map(type => {
              const active = filters.attackTypes.has(type)
              return (
                <button
                  key={type}
                  type="button"
                  className={`filter-chip ${active ? 'active' : ''}`}
                  onClick={() => toggleAttackType(type)}
                >
                  {type.replace(/_/g, ' ')}
                </button>
              )
            })}
          </div>
        </div>

        <div className="filter-group filter-group-input">
          <label htmlFor="filter-ip">Source IP</label>
          <input
            id="filter-ip"
            type="text"
            value={filters.ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="contains..."
          />
        </div>

        <div className="filter-group filter-group-input">
          <label htmlFor="filter-search">Search</label>
          <input
            id="filter-search"
            type="text"
            value={filters.search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="path, query, raw log..."
          />
        </div>

        <label className="filter-toggle">
          <input
            type="checkbox"
            checked={showRawLogs}
            onChange={(e) => onToggleRawLogs(e.target.checked)}
          />
          <span>Show raw logs</span>
        </label>

        <button
          type="button"
          className="filter-clear"
          onClick={clearAll}
          disabled={activeCount === 0}
        >
          {activeCount > 0 ? `Clear (${activeCount})` : 'Clear'}
        </button>
      </div>
    </div>
  )
}
