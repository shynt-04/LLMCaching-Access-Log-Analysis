import { useMemo } from 'react'

/**
 * Secondary filter row: attack-type chips, source-IP filter, raw-log toggle, clear.
 * Severity filtering lives in the statistics bar and free-text search lives in the
 * toolbar (both in AlertDashboard) — this row keeps the remaining filter controls.
 */
export default function AlertFilters({
  alerts,
  filters,
  onChange,
  showRawLogs,
  onToggleRawLogs,
}) {
  const attackTypes = useMemo(() => {
    const set = new Set()
    alerts.forEach(a => set.add(a.analysis?.attack_type || 'unknown'))
    return Array.from(set).sort()
  }, [alerts])

  const toggleAttackType = (type) => {
    const next = new Set(filters.attackTypes)
    next.has(type) ? next.delete(type) : next.add(type)
    onChange({ ...filters, attackTypes: next })
  }

  const setIp = (ip) => onChange({ ...filters, ip })

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
    <div className="filter-row">
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

      <div className="filter-group">
        <label htmlFor="filter-ip">Host</label>
        <input
          id="filter-ip"
          className="filter-input"
          type="text"
          value={filters.ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="IP contains…"
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
  )
}
