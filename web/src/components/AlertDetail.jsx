import { useState } from 'react'

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

/** Collapsible section used throughout the drawer body. */
function Section({ title, children, empty, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="dsection">
      <div className="dsection-head" onClick={() => setOpen(o => !o)}>
        <span className="dsection-title">{title}</span>
        <span className="dsection-toggle">{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="dsection-body">
          {empty ? <div className="dsection-empty">{empty}</div> : children}
        </div>
      )}
    </div>
  )
}

function LabelValue({ label, value, link, children }) {
  return (
    <div className="lvpair">
      <span className="lvpair-label">{label}</span>
      <span className={`lvpair-value ${link ? 'link' : ''}`}>{children ?? (value || '—')}</span>
    </div>
  )
}

function ScoreRow({ label, value }) {
  const pct = Math.min((value || 0) * 100, 100)
  const cls = pct >= 70 ? 'high' : pct >= 40 ? 'medium' : 'low'
  return (
    <div className="score-row">
      <div className="score-row-head">
        <span>{label}</span>
        <span className="score-value">{(value || 0).toFixed(3)}</span>
      </div>
      <div className="score-track">
        <div className={`score-fill ${cls}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

export default function AlertDetail({ alert, showRawLogs, onClose }) {
  const [tab, setTab] = useState('detail')
  const analysis = alert.analysis || {}
  const severity = getSeverity(alert)
  const attackType = (analysis.attack_type || 'unknown').replace(/_/g, ' ')

  const alertId = alert.line_number !== undefined && alert.line_number !== null
    ? `LINE_${alert.line_number}`
    : (alert.timestamp || 'ALERT')

  const hasCacheInfo = alert.cache_hit || alert.cache_decision_reason
  const similarity = alert.cache_similarity ?? analysis.cache_similarity

  return (
    <div className="drawer-inner" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* ── Header ─────────────────────────────────────────── */}
      <div className="drawer-header">
        <div className="drawer-header-top">
          <div className="drawer-badges">
            <span className="badge-severity badge-noimpact" style={{ background: 'var(--status-new-dot)' }}>New</span>
            <span className={`badge-severity badge-${severity}`}>{severity}</span>
          </div>
          <span className="drawer-title">{alertId}</span>
          <button type="button" className="drawer-close" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="drawer-subline">
          First seen: {alert.timestamp || '—'} · Last update: {alert.timestamp || '—'}
        </div>
      </div>

      {/* ── Metadata row ───────────────────────────────────── */}
      <div className="drawer-meta">
        <div className="drawer-meta-item">
          <span className="drawer-meta-label"><span className="drawer-meta-square" style={{ background: '#1976d2' }} />Source IP</span>
          <span className="drawer-meta-value mono link">{alert.source_ip || '—'}</span>
        </div>
        <div className="drawer-meta-item">
          <span className="drawer-meta-label"><span className="drawer-meta-square" style={{ background: '#e63946' }} />Attack Type</span>
          <span className="drawer-meta-value" style={{ textTransform: 'capitalize' }}>{attackType}</span>
        </div>
        <div className="drawer-meta-item">
          <span className="drawer-meta-label"><span className="drawer-meta-square" style={{ background: '#fb8c00' }} />Method</span>
          <span className="drawer-meta-value mono">{alert.method || '—'} · {alert.status_code ?? '—'}</span>
        </div>
        <div className="drawer-meta-item">
          <span className="drawer-meta-label"><span className="drawer-meta-square" style={{ background: '#43a047' }} />Object</span>
          <span className="drawer-meta-value mono" title={alert.path}>{alert.path || '—'}</span>
        </div>
      </div>

      {/* ── Tabs ───────────────────────────────────────────── */}
      <div className="drawer-tabs">
        <button type="button" className={`drawer-tab ${tab === 'detail' ? 'active' : ''}`} onClick={() => setTab('detail')}>Detail</button>
        <button type="button" className={`drawer-tab ${tab === 'raw' ? 'active' : ''}`} onClick={() => setTab('raw')}>Raw data</button>
        <button type="button" className={`drawer-tab ${tab === 'cache' ? 'active' : ''}`} onClick={() => setTab('cache')}>Cache &amp; detection</button>
      </div>

      {/* ── Body ───────────────────────────────────────────── */}
      {tab === 'raw' ? (
        <div className="drawer-body single">
          <div className="drawer-col drawer-col-left">
            <Section title="Request (decoded)">
              <div className="code-block">
                {alert.method} {alert.path}{alert.query_string ? `?${alert.query_string}` : ''}
              </div>
              {alert.query_string && (
                <div style={{ marginTop: 10 }}>
                  <LabelValue label="Query string"><span className="mono" style={{ wordBreak: 'break-all' }}>{alert.query_string}</span></LabelValue>
                </div>
              )}
            </Section>
            <Section title="Original log line" empty={!alert.raw_line ? 'No raw line available.' : null}>
              {alert.raw_line && <div className="drawer-raw">{alert.raw_line}</div>}
            </Section>
          </div>
          <div className="drawer-col drawer-col-right" />
        </div>
      ) : tab === 'cache' ? (
        <div className="drawer-body single">
          <div className="drawer-col drawer-col-left">
            <Section title="Detection scores">
              <ScoreRow label="Merged" value={alert.merged_score} />
              <ScoreRow label="Rule" value={alert.rule_score} />
              <ScoreRow label="ML" value={alert.ml_score} />
              {analysis.confidence !== undefined && <ScoreRow label="LLM confidence" value={analysis.confidence} />}
            </Section>
            <Section title="Cache policy" empty={!hasCacheInfo ? 'LLM call without cache reuse.' : null}>
              {hasCacheInfo && (
                <>
                  <LabelValue label="Mode" value={alert.cache_policy_mode || analysis.cache_policy_mode || 'attack_type_aware'} />
                  <LabelValue label="Hit type" value={alert.cache_hit_type || analysis.cache_hit_type || 'miss'} />
                  <LabelValue label="Cached type" value={alert.cached_attack_type || analysis.cached_attack_type || '—'} />
                  <LabelValue label="Similarity" value={similarity !== null && similarity !== undefined ? similarity.toFixed(3) : '—'} />
                  <div style={{ marginTop: 8 }} className="detail-text">
                    {alert.cache_decision_reason || analysis.cache_decision_reason || 'LLM call without cache reuse.'}
                  </div>
                </>
              )}
            </Section>
          </div>
          <div className="drawer-col drawer-col-right" />
        </div>
      ) : (
        <div className="drawer-body">
          {/* LEFT */}
          <div className="drawer-col drawer-col-left">
            <Section title="Description" empty={!analysis.explanation ? 'No description provided.' : null}>
              {analysis.explanation && <div className="detail-text">{analysis.explanation}</div>}
            </Section>

            <Section title="References">
              {alert.matched_rules?.length > 0 ? (
                <LabelValue label="Rule id">
                  <span className="mono">{alert.matched_rules.map(r => (typeof r === 'string' ? r : r.name || JSON.stringify(r))).join(', ')}</span>
                </LabelValue>
              ) : (
                <div className="dsection-empty">No matched rules.</div>
              )}
              {analysis.cve_refs?.length > 0 && (
                <div style={{ marginTop: 8 }}>
                  <div className="lvpair-label" style={{ marginBottom: 6 }}>CVE references</div>
                  <div className="tag-list">
                    {analysis.cve_refs.map((cve, i) => (
                      <a key={i} className="tag-chip" href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer">{cve}</a>
                    ))}
                  </div>
                </div>
              )}
            </Section>

            <Section title="Recommended actions" empty={!analysis.recommended_actions?.length ? 'No actions to show.' : null}>
              {analysis.recommended_actions?.length > 0 && (
                <div className="tag-list">
                  {analysis.recommended_actions.map((action, i) => (
                    <span key={i} className="tag-chip">
                      {action === 'block_ip' ? `Block ${alert.source_ip}` :
                       action === 'escalate' ? 'Escalate' :
                       action === 'monitor' ? 'Monitor' :
                       action === 'ignore' ? 'Ignore' : action}
                    </span>
                  ))}
                </div>
              )}
            </Section>
          </div>

          {/* RIGHT */}
          <div className="drawer-col drawer-col-right">
            <Section title="Source event">
              <LabelValue label="Timestamp" value={alert.timestamp} />
              <LabelValue label="Source IP"><span className="mono">{alert.source_ip || '—'}</span></LabelValue>
              <LabelValue label="Method"><span className="mono">{alert.method || '—'}</span></LabelValue>
              <LabelValue label="Status code"><span className="mono">{alert.status_code ?? '—'}</span></LabelValue>
              <LabelValue label="Endpoint"><span className="mono" style={{ wordBreak: 'break-all' }}>{alert.path || '—'}</span></LabelValue>
              {alert.user_agent && <LabelValue label="User agent"><span className="mono">{alert.user_agent}</span></LabelValue>}
            </Section>

            <Section title="Advanced">
              <LabelValue label="Severity"><span className={`badge-severity badge-${severity}`}>{severity}</span></LabelValue>
              <LabelValue label="Attack type"><span style={{ textTransform: 'capitalize' }}>{attackType}</span></LabelValue>
              <LabelValue label="Merged score"><span className="mono">{(alert.merged_score || 0).toFixed(3)}</span></LabelValue>
              <LabelValue label="Rule score"><span className="mono">{(alert.rule_score || 0).toFixed(3)}</span></LabelValue>
              <LabelValue label="ML score"><span className="mono">{(alert.ml_score || 0).toFixed(3)}</span></LabelValue>
              <LabelValue label="Cache">
                <span className={`cache-badge ${alert.cache_hit ? 'hit' : 'miss'}`}>{alert.cache_hit ? 'HIT' : 'MISS'}</span>
              </LabelValue>
            </Section>

            {showRawLogs && alert.raw_line && (
              <Section title="Raw log" defaultOpen={false}>
                <div className="drawer-raw">{alert.raw_line}</div>
              </Section>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
