export default function AlertDetail({ alert }) {
  const analysis = alert.analysis || {}
  const severity = alert.merged_score >= 0.85 ? 'CRITICAL'
    : alert.merged_score >= 0.7 ? 'HIGH'
    : alert.merged_score >= 0.5 ? 'MEDIUM' : 'LOW'

  const severityColor = {
    CRITICAL: 'var(--severity-critical)',
    HIGH: 'var(--severity-high)',
    MEDIUM: 'var(--severity-medium)',
    LOW: 'var(--severity-low)',
  }[severity]

  return (
    <div className="detail-panel">
      {/* Header */}
      <div className="detail-header">
        <div className="detail-attack-type" style={{ color: severityColor }}>
          {(analysis.attack_type || 'Unknown').replace('_', ' ').toUpperCase()}
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <span style={{
            padding: '4px 12px',
            borderRadius: '6px',
            background: `${severityColor}20`,
            color: severityColor,
            fontWeight: 600,
            fontSize: '0.8rem',
          }}>
            {severity}
          </span>
          <span className={`cache-badge ${alert.cache_hit ? 'hit' : 'miss'}`}>
            {alert.cache_hit ? 'Cache Hit' : 'LLM Call'}
          </span>
        </div>
      </div>

      {/* Event info */}
      <div className="detail-section">
        <div className="detail-section-title">Event Information</div>
        <div className="detail-grid">
          <div className="detail-field">
            <label>Timestamp</label>
            <span>{alert.timestamp || '—'}</span>
          </div>
          <div className="detail-field">
            <label>Source IP</label>
            <span>{alert.source_ip}</span>
          </div>
          <div className="detail-field">
            <label>Method</label>
            <span>{alert.method}</span>
          </div>
          <div className="detail-field">
            <label>Status Code</label>
            <span>{alert.status_code}</span>
          </div>
          <div className="detail-field">
            <label>Endpoint</label>
            <span>{alert.path}</span>
          </div>
          <div className="detail-field">
            <label>Window Size</label>
            <span>{alert.window_size} events</span>
          </div>
        </div>
      </div>

      {/* Scores */}
      <div className="detail-section">
        <div className="detail-section-title">Detection Scores</div>
        <ScoreRow label="Merged" value={alert.merged_score} />
        <ScoreRow label="Rule" value={alert.rule_score} />
        <ScoreRow label="ML" value={alert.ml_score} />
        {analysis.confidence !== undefined && (
          <ScoreRow label="LLM Confidence" value={analysis.confidence} />
        )}
      </div>

      {/* LLM Explanation */}
      {analysis.explanation && (
        <div className="detail-section">
          <div className="detail-section-title">LLM Explanation</div>
          <div className="detail-explanation">
            {analysis.explanation}
          </div>
        </div>
      )}

      {/* Payload */}
      {alert.path && (
        <div className="detail-section">
          <div className="detail-section-title">Request (decoded)</div>
          <div className="detail-payload">
            <div>{alert.method} {alert.path}{alert.query_string ? `?${alert.query_string}` : ''}</div>
            {alert.query_string && (
              <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid var(--border)' }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', display: 'block', marginBottom: '4px' }}>Query String</span>
                <span style={{ wordBreak: 'break-all' }}>{alert.query_string}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Original Log Line */}
      {alert.raw_line && (
        <div className="detail-section">
          <div className="detail-section-title">Original Log Line</div>
          <div className="detail-payload" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {alert.raw_line}
          </div>
        </div>
      )}

      {/* Matched rules */}
      {alert.matched_rules?.length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">Matched Rules</div>
          <div className="detail-actions">
            {alert.matched_rules.map((rule, i) => (
              <span key={i} className="action-tag">{typeof rule === 'string' ? rule : rule.name || JSON.stringify(rule)}</span>
            ))}
          </div>
        </div>
      )}

      {/* Recommended actions */}
      {analysis.recommended_actions?.length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">Recommended Actions</div>
          <div className="detail-actions">
            {analysis.recommended_actions.map((action, i) => (
              <span key={i} className="action-tag">
                {action === 'block_ip' ? `Block ${alert.source_ip}` :
                 action === 'escalate' ? 'Escalate' :
                 action === 'monitor' ? 'Monitor' :
                 action === 'ignore' ? 'Ignore' : action}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* CVE references */}
      {analysis.cve_refs?.length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">CVE References</div>
          <div className="detail-actions">
            {analysis.cve_refs.map((cve, i) => (
              <a
                key={i}
                className="action-tag"
                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ textDecoration: 'none' }}
              >
                {cve}
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Latency info — hidden for SIEM-like presentation
      {alert.latency_ms !== undefined && (
        <div className="detail-section">
          <div className="detail-section-title">Performance</div>
          <div className="detail-grid">
            <div className="detail-field">
              <label>Processing Latency</label>
              <span>{alert.latency_ms} ms</span>
            </div>
            {analysis.ttft_ms !== null && analysis.ttft_ms !== undefined && (
              <div className="detail-field">
                <label>TTFT</label>
                <span>{analysis.ttft_ms} ms</span>
              </div>
            )}
          </div>
        </div>
      )}
      */}
    </div>
  )
}

function ScoreRow({ label, value }) {
  const pct = Math.min(value * 100, 100)
  const cls = pct >= 70 ? 'high' : pct >= 40 ? 'medium' : 'low'

  return (
    <div style={{ marginBottom: '8px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{label}</span>
      </div>
      <div className="score-bar-container">
        <div className="score-bar">
          <div
            className={`score-bar-fill ${cls}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <span className="score-value">{(value || 0).toFixed(3)}</span>
      </div>
    </div>
  )
}
