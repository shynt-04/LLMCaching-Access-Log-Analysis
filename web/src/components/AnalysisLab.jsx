import { useState, useRef } from 'react'

export default function AnalysisLab({
  onStartAnalysis,
  progress,
  metrics,
  activeSession,
  alerts,
}) {
  const [file, setFile] = useState(null)
  const [source, setSource] = useState('auto')
  const [useCache, setUseCache] = useState(true)
  const [isRunning, setIsRunning] = useState(false)
  const [history, setHistory] = useState([])  // store past session metrics
  const fileRef = useRef(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!file) return

    setIsRunning(true)
    const result = await onStartAnalysis(file, source, useCache)
    if (result) {
      // After completion, metrics will be streamed via WS
    }
    setIsRunning(false)
  }

  // Gather all metrics (current + history) for comparison table
  const allMetrics = metrics ? Object.entries(metrics) : []

  // Separate no-cache and with-cache runs for side-by-side comparison
  const noCacheRun = allMetrics.find(([, m]) => m.use_cache === false)?.[1]
  const withCacheRun = allMetrics.find(([, m]) => m.use_cache === true)?.[1]

  return (
    <div className="page">
      <h1 className="page-title">Analysis Lab</h1>

      {/* Upload section */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">Upload Log File</div>
        <div className="lab-upload">
          <form className="upload-form" onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="log-file">Log File</label>
              <input
                id="log-file"
                type="file"
                ref={fileRef}
                accept=".log,.txt"
                onChange={(e) => setFile(e.target.files[0])}
              />
            </div>

            <div className="form-group">
              <label htmlFor="log-source">Source</label>
              <select
                id="log-source"
                value={source}
                onChange={(e) => setSource(e.target.value)}
              >
                <option value="auto">Auto Detect</option>
                <option value="apache">Apache</option>
                <option value="nginx">Nginx</option>
              </select>
            </div>

            <div className="form-group">
              <label>Cache Mode</label>
              <div className="cache-toggle">
                <button
                  type="button"
                  className={useCache ? '' : 'active'}
                  onClick={() => setUseCache(false)}
                >
                  No Cache
                </button>
                <button
                  type="button"
                  className={useCache ? 'active' : ''}
                  onClick={() => setUseCache(true)}
                >
                  With Cache
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="btn-analyze"
              disabled={!file || isRunning}
            >
              {isRunning ? 'Processing…' : '▶ Run Analysis'}
            </button>
          </form>
        </div>
      </div>

      {/* Progress bar */}
      {progress && (
        <div className="card" style={{ marginBottom: '20px' }}>
          <div className="card-header">Processing Progress</div>
          <div className="progress-section">
            <div className="progress-bar-outer">
              <div
                className="progress-bar-inner"
                style={{
                  width: progress.total > 0
                    ? `${(progress.processed / progress.total) * 100}%`
                    : '0%'
                }}
              />
            </div>
            <div className="progress-text">
              <span>{progress.processed} / {progress.total} lines processed</span>
              <span>{alerts.length} alerts found</span>
            </div>
          </div>
        </div>
      )}

      {/* Benchmark comparison */}
      {allMetrics.length > 0 && (
        <div className="card">
          <div className="card-header">Benchmark Results</div>
          <div className="benchmark-section">
            {/* Show latest run */}
            {allMetrics.map(([sid, m]) => (
              <div key={sid} style={{ marginBottom: '24px' }}>
                <h3 style={{
                  fontSize: '0.9rem',
                  color: 'var(--text-secondary)',
                  marginBottom: '12px',
                }}>
                  Session {sid} — {m.use_cache ? '✅ With Cache' : '❌ No Cache'}
                </h3>
                <table className="benchmark-table">
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Total Lines</td>
                      <td>{m.total_lines}</td>
                    </tr>
                    <tr>
                      <td>Total Alerts</td>
                      <td>{m.total_alerts}</td>
                    </tr>
                    <tr>
                      <td>Processing Time</td>
                      <td>{m.total_time_s}s</td>
                    </tr>
                    <tr>
                      <td>Throughput</td>
                      <td>{m.throughput_ev_s} ev/s</td>
                    </tr>
                    <tr>
                      <td>Latency P95</td>
                      <td>{m.latency_p95_ms} ms</td>
                    </tr>
                    <tr>
                      <td>Latency Avg</td>
                      <td>{m.latency_avg_ms} ms</td>
                    </tr>
                    <tr>
                      <td>Cache Hits</td>
                      <td>{m.cache_hits}</td>
                    </tr>
                    <tr>
                      <td>Cache Hit Rate</td>
                      <td>{(m.cache_hit_rate * 100).toFixed(1)}%</td>
                    </tr>
                    <tr>
                      <td>LLM Calls</td>
                      <td>{m.total_llm_calls}</td>
                    </tr>
                    <tr>
                      <td>Total Input Tokens</td>
                      <td>{m.total_input_tokens}</td>
                    </tr>
                    <tr>
                      <td>Total Output Tokens</td>
                      <td>{m.total_output_tokens}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            ))}

            {/* Side-by-side comparison if both runs exist */}
            {noCacheRun && withCacheRun && (
              <div>
                <h3 style={{
                  fontSize: '0.9rem',
                  color: 'var(--accent-cyan)',
                  marginBottom: '12px',
                  marginTop: '24px',
                }}>
                  ⚡ Comparison: No Cache vs With Cache
                </h3>
                <table className="benchmark-table">
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>No Cache</th>
                      <th>With Cache</th>
                      <th>Delta</th>
                    </tr>
                  </thead>
                  <tbody>
                    <CompareRow
                      label="Latency P95 (ms)"
                      a={noCacheRun.latency_p95_ms}
                      b={withCacheRun.latency_p95_ms}
                      lowerIsBetter
                    />
                    <CompareRow
                      label="Throughput (ev/s)"
                      a={noCacheRun.throughput_ev_s}
                      b={withCacheRun.throughput_ev_s}
                    />
                    <CompareRow
                      label="LLM Calls"
                      a={noCacheRun.total_llm_calls}
                      b={withCacheRun.total_llm_calls}
                      lowerIsBetter
                    />
                    <CompareRow
                      label="Cache Hit Rate"
                      a={(noCacheRun.cache_hit_rate * 100).toFixed(1) + '%'}
                      b={(withCacheRun.cache_hit_rate * 100).toFixed(1) + '%'}
                      rawDelta={`+${((withCacheRun.cache_hit_rate - noCacheRun.cache_hit_rate) * 100).toFixed(1)}pp`}
                    />
                    <CompareRow
                      label="Processing Time (s)"
                      a={noCacheRun.total_time_s}
                      b={withCacheRun.total_time_s}
                      lowerIsBetter
                    />
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function CompareRow({ label, a, b, lowerIsBetter = false, rawDelta = null }) {
  let deltaText = rawDelta
  let deltaClass = ''

  if (!rawDelta && typeof a === 'number' && typeof b === 'number' && a !== 0) {
    const pctChange = ((b - a) / a) * 100
    deltaText = `${pctChange > 0 ? '+' : ''}${pctChange.toFixed(1)}%`

    if (lowerIsBetter) {
      deltaClass = pctChange < 0 ? 'delta-positive' : 'delta-negative'
    } else {
      deltaClass = pctChange > 0 ? 'delta-positive' : 'delta-negative'
    }
  }

  return (
    <tr>
      <td>{label}</td>
      <td>{a}</td>
      <td>{b}</td>
      <td className={deltaClass}>{deltaText || '—'}</td>
    </tr>
  )
}
