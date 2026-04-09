import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [findings, setFindings] = useState([]);
  const [logs, setLogs] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [status, setStatus] = useState("Ready");
  const [activeTab, setActiveTab] = useState("dashboard");

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
      const res = await axios.get(`${API}/logs`);
      setLogs(res.data.logs || []);
    } catch (e) {
      console.error(e);
    }
  };

  const runScan = async () => {
    setScanning(true);
    setStatus("Scanning AWS resources...");
    setFindings([]);
    try {
      const res = await axios.get(`${API}/scan`);
      setFindings(res.data.findings || []);
      setStatus("Scan complete");
      fetchLogs();
    } catch (e) {
      setStatus("Scan failed — check API");
    }
    setScanning(false);
  };

  const critical = findings.filter(f => f.ai_risk_level === "CRITICAL").length;
  const high = findings.filter(f => f.ai_risk_level === "HIGH").length;
  const medium = findings.filter(f => f.ai_risk_level === "MEDIUM").length;
  const low = findings.filter(f => f.ai_risk_level === "LOW").length;
  const aiScore = findings.length
    ? Math.round(findings.reduce((a, f) => a + f.ai_score, 0) / findings.length)
    : 0;

  const getBarColor = (score) => {
    if (score >= 80) return "#fc8181";
    if (score >= 60) return "#f6ad55";
    if (score >= 40) return "#63b3ed";
    return "#68d391";
  };

  return (
    <div className="app">
      {/* Header */}
      <div className="header">
        <div className="header-left">
          <h1>🛡️ AutoShield AI</h1>
          <p>AI-Powered Cloud Security Automation Platform</p>
        </div>
        <button className="scan-btn" onClick={runScan} disabled={scanning}>
          {scanning ? "⏳ Scanning..." : "🔍 Run Security Scan"}
        </button>
      </div>

      {/* Tabs */}
      <div style={{ padding: "20px 40px 0", borderBottom: "1px solid #1e3a5f", display: "flex", gap: "24px" }}>
        {["dashboard", "findings", "logs"].map(tab => (
          <div
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: "10px 4px",
              cursor: "pointer",
              fontSize: "14px",
              fontWeight: "600",
              textTransform: "capitalize",
              color: activeTab === tab ? "#63b3ed" : "#4a5568",
              borderBottom: activeTab === tab ? "2px solid #63b3ed" : "2px solid transparent",
              transition: "all 0.2s",
              letterSpacing: "0.5px"
            }}
          >
            {tab === "dashboard" ? "📊 Dashboard" : tab === "findings" ? "⚠️ Findings" : "📋 Audit Logs"}
          </div>
        ))}
      </div>

      <div className="main" style={{ paddingBottom: "60px" }}>

        {/* Dashboard Tab */}
        {activeTab === "dashboard" && (
          <>
            {/* Score Cards */}
            <div className="score-section">
              <div className="score-card critical">
                <div className="number">{critical}</div>
                <div className="label">🔴 Critical</div>
              </div>
              <div className="score-card high">
                <div className="number">{high}</div>
                <div className="label">🟠 High</div>
              </div>
              <div className="score-card medium">
                <div className="number">{medium}</div>
                <div className="label">🔵 Medium</div>
              </div>
              <div className="score-card low">
                <div className="number">{low}</div>
                <div className="label">🟢 Low</div>
              </div>
              <div className="score-card total">
                <div className="number">{findings.length}</div>
                <div className="label">📊 Total Issues</div>
              </div>
              <div className="score-card ai-score">
                <div className="number">{aiScore}</div>
                <div className="label">🤖 AI Score /100</div>
              </div>
            </div>

            {/* Empty or scan prompt */}
            {findings.length === 0 && !scanning && (
              <div className="empty-state">
                <div className="icon">🛡️</div>
                <p>Click <strong>"Run Security Scan"</strong> to analyze your AWS environment</p>
              </div>
            )}

            {scanning && (
              <div className="loading">
                <div className="spinner"></div>
                Scanning AWS resources...
              </div>
            )}

            {/* Quick findings preview */}
            {findings.length > 0 && !scanning && (
              <>
                <div className="section-title">Recent Findings</div>
                <div className="findings-grid">
                  {findings.slice(0, 4).map((f, i) => (
                    <div key={i} className={`finding-card ${f.ai_risk_level}`}>
                      <div className="finding-header">
                        <span className={`resource-type ${f.resource_type}`}>{f.resource_type}</span>
                        <span className={`risk-badge ${f.ai_risk_level}`}>{f.ai_risk_level}</span>
                      </div>
                      <div className="resource-name">{f.resource}</div>
                      <div className="issue-text">{f.issue}</div>
                      <div className="ai-score-bar">
                        <div className="bar-label">
                          <span>AI Risk Score</span>
                          <span>{f.ai_score}/100</span>
                        </div>
                        <div className="bar-track">
                          <div className="bar-fill" style={{ width: `${f.ai_score}%`, background: getBarColor(f.ai_score) }}></div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </>
        )}

        {/* Findings Tab */}
        {activeTab === "findings" && (
          <>
            <div className="section-title" style={{ marginTop: "10px" }}>All Security Findings</div>
            {findings.length === 0 ? (
              <div className="empty-state">
                <div className="icon">🔍</div>
                <p>No findings yet — run a scan first!</p>
              </div>
            ) : (
              <div className="findings-grid findings-section">
                {findings.map((f, i) => (
                  <div key={i} className={`finding-card ${f.ai_risk_level}`}>
                    <div className="finding-header">
                      <span className={`resource-type ${f.resource_type}`}>{f.resource_type}</span>
                      <span className={`risk-badge ${f.ai_risk_level}`}>{f.ai_risk_level}</span>
                    </div>
                    <div className="resource-name">{f.resource}</div>
                    <div className="issue-text">{f.issue}</div>
                    <div className="ai-score-bar">
                      <div className="bar-label">
                        <span>AI Risk Score</span>
                        <span>{f.ai_score}/100</span>
                      </div>
                      <div className="bar-track">
                        <div className="bar-fill" style={{ width: `${f.ai_score}%`, background: getBarColor(f.ai_score) }}></div>
                      </div>
                    </div>
                    <div className="recommendation">💡 {f.recommendation}</div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {/* Logs Tab */}
        {activeTab === "logs" && (
          <>
            <div className="section-title" style={{ marginTop: "10px" }}>Audit Log History</div>
            {logs.length === 0 ? (
              <div className="empty-state">
                <div className="icon">📋</div>
                <p>No logs yet — run a scan first!</p>
              </div>
            ) : (
              <table className="logs-table">
                <thead>
                  <tr>
                    <th>Scan ID</th>
                    <th>Timestamp</th>
                    <th>AI Score</th>
                    <th>Total</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Low</th>
                  </tr>
                </thead>
                <tbody>
                  {[...logs].reverse().map((log, i) => (
                    <tr key={i}>
                      <td style={{ color: "#63b3ed", fontFamily: "monospace" }}>{log.scan_id}</td>
                      <td>{log.timestamp}</td>
                      <td style={{ color: getBarColor(log.overall_score), fontWeight: "700" }}>{log.overall_score}/100</td>
                      <td>{log.total_issues}</td>
                      <td style={{ color: "#fc8181" }}>{log.critical}</td>
                      <td style={{ color: "#f6ad55" }}>{log.high}</td>
                      <td style={{ color: "#68d391" }}>{log.low}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </div>

      {/* Status Bar */}
      <div className="status-bar">
        <div className="status-dot"></div>
        AutoShield AI — {status}
      </div>
    </div>
  );
}

export default App;