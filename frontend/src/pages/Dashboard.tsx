import {useCallback, useEffect, useMemo, useState, type ReactNode} from 'react'
import {Area, Gauge, Radar as RadarChart} from '@ant-design/charts'
import {Alert, Badge, Button, Card, Progress, Segmented, Skeleton, Space, Statistic, Tag, Tooltip, Typography} from 'antd'
import {InfoCircleOutlined, ReloadOutlined} from '@ant-design/icons'
import {ChartSpline, GaugeIcon, Kanban, PackageSearch, Radar as RadarIcon, RadioTower, ScanSearch, ShieldAlert, Target, TextSearch, TriangleAlert, Workflow} from 'lucide-react'
import {fetchDashboardOverview, type DashboardHighlight, type DashboardKeyword, type DashboardLabelValue, type DashboardMeanTime, type DashboardMitreSeverityCell, type DashboardOverview, type DashboardRiskArtifact, type DashboardWindow} from '../api/dashboard'
import {severityColors} from '../theme'
import './Dashboard.css'

const {Text} = Typography

const windowOptions: { label: string; value: DashboardWindow }[] = [
  { label: '24h', value: '24h' },
  { label: '7d', value: '7d' },
  { label: '30d', value: '30d' },
]
const chartTheme = 'classicDark' as const
const lucideIconProps = { size: 16, strokeWidth: 2 }

function hasValues(data: DashboardLabelValue[]) {
  return data.some((item) => item.value > 0)
}

function formatNumber(value: number | null | undefined) {
  if (value === null || value === undefined) return 'N/A'
  return value.toLocaleString()
}

function formatPercent(value: number | null | undefined) {
  if (value === null || value === undefined) return 'N/A'
  return `${value.toLocaleString()}%`
}

function formatDuration(seconds: number | null | undefined) {
  if (seconds === null || seconds === undefined) return 'N/A'
  let remaining = Math.max(0, Math.round(seconds))
  const days = Math.floor(remaining / 86400)
  remaining %= 86400
  const hours = Math.floor(remaining / 3600)
  remaining %= 3600
  const minutes = Math.floor(remaining / 60)
  const restSeconds = remaining % 60
  const parts = [
    days ? `${days}d` : '',
    hours ? `${hours}h` : '',
    minutes ? `${minutes}m` : '',
    !days && !hours && !minutes ? `${restSeconds}s` : '',
  ].filter(Boolean)
  return parts.slice(0, 2).join(' ')
}

function severityColor(severity: string) {
  return severityColors[severity] || '#1677ff'
}

function generatedAtLabel(value: string | undefined) {
  if (!value) return 'Waiting for telemetry'
  return `Last refresh ${new Date(value).toLocaleString()}`
}

function CyberEmpty({ title = 'Signal Quiet', description = 'No telemetry in this window.' }: { title?: string; description?: string }) {
  return (
    <div className="dashboard-empty">
      <RadioTower size={22} strokeWidth={1.8} />
      <strong>{title}</strong>
      <span>{description}</span>
    </div>
  )
}

function CyberCard({ title, extra, children, className = '' }: { title: ReactNode; extra?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <Card
      className={`dashboard-card ${className}`}
      title={<span className="dashboard-card-title">{title}</span>}
      extra={extra}
      styles={{ body: { padding: 16 } }}
    >
      {children}
    </Card>
  )
}

function MetricCard({
  title,
  value,
  suffix,
  tooltip,
  accent = '#1677ff',
  sub,
}: {
  title: string
  value: ReactNode
  suffix?: ReactNode
  tooltip?: string
  accent?: string
  sub?: ReactNode
}) {
  const statisticTitle = (
    <Space size={6}>
      <span>{title}</span>
      {tooltip && (
        <Tooltip title={tooltip}>
          <InfoCircleOutlined />
        </Tooltip>
      )}
    </Space>
  )

  return (
    <Card className="dashboard-metric-card" style={{ '--metric-color': accent } as React.CSSProperties} styles={{ body: { padding: 16 } }}>
      <Statistic title={statisticTitle} value={value as string | number} suffix={suffix} styles={{ content: { color: '#f5faff' } }} />
      {sub && <div className="dashboard-metric-sub">{sub}</div>}
    </Card>
  )
}

function MeanTimeCard({ title, metric, tooltip, accent }: { title: string; metric: DashboardMeanTime; tooltip: string; accent: string }) {
  return (
    <MetricCard
      title={title}
      value={formatDuration(metric.seconds)}
      tooltip={tooltip}
      accent={accent}
      sub={`${metric.sample_count} valid sample${metric.sample_count === 1 ? '' : 's'}`}
    />
  )
}

function RiskPostureCard({ data, loading }: { data: DashboardOverview | null; loading: boolean }) {
  const riskIndex = data?.summary.active_risk_index ?? 0
  const clampedRiskIndex = Math.min(100, Math.max(0, riskIndex))
  const gaugeConfig = useMemo(() => ({
    data: {
      percent: clampedRiskIndex / 100,
      thresholds: [0.55, 0.8, 1],
    },
    height: 190,
    theme: chartTheme,
    scale: {
      color: {
        range: ['#52c41a', '#fadb14', '#fa8c16'],
      },
    },
    style: {
      arcLineWidth: 9,
      pointerLineWidth: 3,
      pointerLineCap: 'round',
      pointerStroke: '#69b1ff',
      pinR: 7,
      pinFill: '#061528',
      pinStroke: '#69b1ff',
      textContent: () => '',
    },
  }), [clampedRiskIndex])

  return (
    <CyberCard
      className="dashboard-risk-card"
      title={<><ShieldAlert {...lucideIconProps} /> Active Risk Index</>}
      extra={(
        <Tooltip title="Weighted risk-pressure index based on open cases, active alerts, failed playbooks, and severity weights.">
          <InfoCircleOutlined />
        </Tooltip>
      )}
    >
      {loading && !data ? (
        <Skeleton active paragraph={{ rows: 4 }} />
      ) : (
        <div className="dashboard-risk-body">
          <div className="dashboard-risk-gauge">
            <Gauge {...gaugeConfig} />
          </div>
          <div className="dashboard-risk-score">
            <div className="dashboard-risk-value">{riskIndex}</div>
            <div className="dashboard-risk-label">weighted pressure / 100</div>
            <div className="dashboard-risk-meta">
              <div className="dashboard-chip"><span>Open cases</span><span>{formatNumber(data?.summary.open_cases)}</span></div>
              <div className="dashboard-chip"><span>Critical cases</span><span>{formatNumber(data?.summary.open_critical_cases)}</span></div>
              <div className="dashboard-chip"><span>Critical/High alerts</span><span>{formatNumber(data?.summary.critical_high_alerts)}</span></div>
            </div>
          </div>
        </div>
      )}
    </CyberCard>
  )
}

function statusColor(status: string) {
  const colors: Record<string, string> = {
    New: '#13c2c2',
    'In Progress': '#1677ff',
    'On Hold': '#faad14',
    Resolved: '#52c41a',
    Closed: '#8c8c8c',
  }
  return colors[status] || '#1677ff'
}

function signalColor(index: number) {
  return ['#69b1ff', '#13c2c2', '#b37feb', '#f759ab', '#faad14', '#52c41a'][index % 6]
}

function ChartPanel({ title, children, compact = false, className = '' }: { title: ReactNode; children: ReactNode; compact?: boolean; className?: string }) {
  return (
    <CyberCard title={title} className={className}>
      <div className={`dashboard-panel-body${compact ? ' compact' : ''}`}>{children}</div>
    </CyberCard>
  )
}

function AlertTrend({ data }: { data: DashboardLabelValue[] }) {
  const config = useMemo(() => ({
    data,
    xField: 'label',
    yField: 'value',
    height: 150,
    autoFit: true,
    smooth: true,
    colorField: 'value',
    theme: chartTheme,
  }), [data])

  if (!hasValues(data)) return <CyberEmpty />
  return <Area {...config} />
}

function SeverityPressure({ data }: { data: DashboardLabelValue[] }) {
  const visibleData = data.filter((item) => item.label !== 'Info')
  const maxValue = Math.max(...visibleData.map((item) => item.value), 0)
  const total = visibleData.reduce((sum, item) => sum + item.value, 0)

  if (!hasValues(visibleData)) return <CyberEmpty />

  return (
    <div className="dashboard-severity-pressure">
      {visibleData.map((item) => {
        const pressure = maxValue === 0 ? 0 : Math.round((item.value / maxValue) * 100)
        const share = total === 0 ? 0 : Math.round((item.value / total) * 100)
        return (
          <div className="dashboard-severity-row" key={item.label}>
            <div className="dashboard-severity-header">
              <span className="dashboard-severity-name">
                <span className="dashboard-severity-dot" style={{ background: severityColor(item.label) }} />
                {item.label}
              </span>
              <span className="dashboard-severity-value">{item.value}</span>
            </div>
            <Progress
              percent={pressure}
              showInfo={false}
              strokeColor={severityColor(item.label)}
              railColor="rgba(255,255,255,0.08)"
            />
            <div className="dashboard-severity-share">{share}% of severity telemetry</div>
          </div>
        )
      })}
    </div>
  )
}

function CaseWorkloadState({ data }: { data: DashboardLabelValue[] }) {
  const visibleData = data.filter((item) => item.value > 0)
  const maxValue = Math.max(...visibleData.map((item) => item.value), 0)
  const total = visibleData.reduce((sum, item) => sum + item.value, 0)

  if (!hasValues(visibleData)) return <CyberEmpty />

  return (
    <div className="dashboard-workload-state">
      {visibleData.map((item) => {
        const percent = maxValue === 0 ? 0 : Math.round((item.value / maxValue) * 100)
        const share = total === 0 ? 0 : Math.round((item.value / total) * 100)
        return (
          <div className="dashboard-workload-row" key={item.label}>
            <div className="dashboard-workload-head">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
            <Progress percent={percent} showInfo={false} strokeColor={statusColor(item.label)} railColor="rgba(255,255,255,0.08)" />
            <span className="dashboard-workload-share">{share}% of workload</span>
          </div>
        )
      })}
    </div>
  )
}

function ProductCategorySignals({ data }: { data: DashboardLabelValue[] }) {
  const visibleData = data.filter((item) => item.value > 0)
  const maxValue = Math.max(...visibleData.map((item) => item.value), 0)
  const total = visibleData.reduce((sum, item) => sum + item.value, 0)

  if (!hasValues(visibleData)) return <CyberEmpty />

  return (
    <div className="dashboard-signal-rank">
      {visibleData.map((item, index) => {
        const percent = maxValue === 0 ? 0 : Math.round((item.value / maxValue) * 100)
        const share = total === 0 ? 0 : Math.round((item.value / total) * 100)
        return (
          <div className="dashboard-signal-row" key={item.label}>
            <span className="dashboard-signal-index">{String(index + 1).padStart(2, '0')}</span>
            <div className="dashboard-signal-main">
              <div className="dashboard-signal-head">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </div>
              <div className="dashboard-signal-track">
                <span style={{ width: `${percent}%`, background: signalColor(index) }} />
              </div>
              <div className="dashboard-signal-meta">
                <span>{share}% of product telemetry</span>
                <span>{percent}% relative pressure</span>
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

function ThreatKeywordCloud({ data }: { data: DashboardKeyword[] }) {
  const visibleData = data.slice(0, 28)
  const values = visibleData.map((item) => item.value)
  const minValue = Math.min(...values)
  const maxValue = Math.max(...values)

  if (visibleData.length === 0) return <CyberEmpty title="No Threat Keywords" />

  return (
    <div className="dashboard-keyword-cloud">
      {visibleData.map((item, index) => {
        const ratio = maxValue === minValue ? 0.5 : (item.value - minValue) / (maxValue - minValue)
        const fontSize = Math.round(12 + ratio * 18)
        return (
          <span
            className="dashboard-keyword-token"
            key={`${item.text}-${index}`}
            title={`${item.text}: ${item.value}`}
            style={{
              color: signalColor(index),
              fontSize,
              opacity: 0.68 + ratio * 0.32,
              fontWeight: ratio > 0.62 ? 800 : ratio > 0.32 ? 700 : 500,
            }}
          >
            {item.text}
          </span>
        )
      })}
    </div>
  )
}

function SecurityDomainRadar({ data }: { data: DashboardLabelValue[] }) {
  const visibleData = data.filter((item) => item.value > 0)
  if (!hasValues(visibleData)) return <CyberEmpty title="No Domain Signals" />
  const maxValue = Math.max(...visibleData.map((item) => item.value), 1)
  const config = {
    data: visibleData,
    xField: 'label',
    yField: 'value',
    height: 260,
    autoFit: true,
    theme: chartTheme,
    coordinateType: 'polar' as const,
    scale: {
      y: {
        domain: [0, maxValue],
        nice: true,
      },
    },
    area: {
      style: {
        fill: '#1677ff',
        fillOpacity: 0.18,
      },
    },
    line: {
      style: {
        stroke: '#69b1ff',
        lineWidth: 2,
      },
    },
    point: {
      style: {
        fill: '#13c2c2',
        stroke: '#f5faff',
        lineWidth: 1,
        r: 3,
      },
    },
  }

  return <RadarChart {...config} />
}

function MitreSeverityMatrix({ data }: { data: DashboardMitreSeverityCell[] }) {
  const visibleCells = data.filter((item) => item.value > 0)
  const tactics = [...new Set(data.map((item) => item.tactic))]
  const severities = [...new Set(data.map((item) => item.severity))]
  const maxValue = Math.max(...visibleCells.map((item) => item.value), 0)
  const cellMap = new Map(data.map((item) => [`${item.severity}:${item.tactic}`, item.value]))

  if (tactics.length === 0) return <CyberEmpty title="No MITRE Tactics" />

  return (
    <div className="dashboard-mitre-matrix">
      <div className="dashboard-mitre-head" style={{ gridTemplateColumns: `72px repeat(${tactics.length}, minmax(0, 1fr))` }}>
        <span>Severity</span>
        {tactics.map((tactic) => <span key={tactic} title={tactic}>{tactic}</span>)}
      </div>
      {severities.map((severity) => (
        <div className="dashboard-mitre-row" key={severity} style={{ gridTemplateColumns: `72px repeat(${tactics.length}, minmax(0, 1fr))` }}>
          <span className="dashboard-mitre-severity" title={severity}>{severity}</span>
          {tactics.map((tactic) => {
            const value = cellMap.get(`${severity}:${tactic}`) || 0
            const intensity = maxValue === 0 ? 0 : value / maxValue
            const color = severityColor(severity)
            return (
              <span
                className="dashboard-mitre-cell"
                key={`${severity}-${tactic}`}
                title={`${severity} / ${tactic}: ${value}`}
                style={{
                  background: value > 0 ? `linear-gradient(135deg, ${color}${Math.round(34 + intensity * 108).toString(16).padStart(2, '0')}, rgba(255,255,255,0.04))` : 'rgba(255,255,255,0.035)',
                  borderColor: value > 0 ? `${color}66` : 'rgba(255,255,255,0.06)',
                  color: value > 0 ? '#f5faff' : 'rgba(255,255,255,0.24)',
                  boxShadow: value > 0 ? `0 0 ${Math.round(8 + intensity * 18)}px ${color}33` : undefined,
                }}
              >
                {value}
              </span>
            )
          })}
        </div>
      ))}
    </div>
  )
}

function AutomationPanel({ data }: { data: DashboardLabelValue[] }) {
  const total = data.reduce((sum, item) => sum + item.value, 0)
  if (total === 0) return <CyberEmpty title="No Playbook Telemetry" description="No playbooks executed in this window." />

  return (
    <div className="dashboard-mini-list">
      {data.map((item) => {
        const percent = total === 0 ? 0 : Math.round((item.value / total) * 100)
        const color = item.label === 'Failed' ? '#ff4d4f' : item.label === 'Success' ? '#52c41a' : item.label === 'Running' ? '#1677ff' : '#faad14'
        return (
          <div className="dashboard-progress-row" key={item.label}>
            <div className="dashboard-progress-header">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
            <Progress percent={percent} showInfo={false} strokeColor={color} railColor="rgba(255,255,255,0.08)" />
          </div>
        )
      })}
    </div>
  )
}

function CoveragePanel({ data }: { data: DashboardOverview }) {
  const rows = [
    { label: 'Enrichment coverage', value: data.coverage.enrichment_coverage, color: '#13c2c2' },
    { label: 'Playbook coverage', value: data.coverage.playbook_coverage, color: '#1677ff' },
  ]

  return (
    <div className="dashboard-mini-list">
      {rows.map((row) => (
        <div className="dashboard-progress-row" key={row.label}>
          <div className="dashboard-progress-header">
            <span>{row.label}</span>
            <strong>{formatPercent(row.value)}</strong>
          </div>
          <Progress percent={row.value || 0} showInfo={false} strokeColor={row.color} railColor="rgba(255,255,255,0.08)" />
        </div>
      ))}
      <div className="dashboard-chip"><span>Knowledge extracted</span><span>{data.coverage.knowledge_records}</span></div>
      <div className="dashboard-chip"><span>Artifacts observed</span><span>{data.coverage.artifact_records}</span></div>
      <div className="dashboard-chip"><span>Enrichments produced</span><span>{data.coverage.enrichment_records}</span></div>
    </div>
  )
}

function RiskArtifacts({ artifacts }: { artifacts: DashboardRiskArtifact[] }) {
  if (artifacts.length === 0) return <CyberEmpty title="No Risky Entities" description="No linked artifacts with alert pressure in this window." />

  return (
    <div className="dashboard-artifact-grid">
      {artifacts.map((artifact) => (
        <div className="dashboard-artifact-card" key={artifact.id}>
          <div className="dashboard-artifact-value" title={artifact.value}>{artifact.value || 'Unknown artifact'}</div>
          <div className="dashboard-artifact-meta">
            <Tag color="blue">{artifact.type || 'Unknown'}</Tag>
            <Tag color="purple">{artifact.role || 'Unknown'}</Tag>
          </div>
          <div className="dashboard-chip"><span>Risk score</span><span>{artifact.risk_score}</span></div>
          <div className="dashboard-chip"><span>Linked alerts</span><span>{artifact.alert_count}</span></div>
        </div>
      ))}
    </div>
  )
}

function HighlightStream({ highlights }: { highlights: DashboardHighlight[] }) {
  if (highlights.length === 0) return <CyberEmpty title="No High-Severity Events" description="Critical and high signals are quiet in this window." />

  return (
    <div className="dashboard-event-stream">
      {highlights.map((item) => (
        <div className="dashboard-event" key={`${item.kind}-${item.id}`} style={{ '--event-color': severityColor(item.severity) } as React.CSSProperties}>
          <div className="dashboard-event-title">
            <strong title={item.title}>{item.title || item.readable_id}</strong>
            <Badge color={severityColor(item.severity)} text={item.severity || 'Unknown'} />
          </div>
          <div className="dashboard-event-meta">
            <span>{item.kind.toUpperCase()}</span>
            <span>{item.readable_id}</span>
            <span>{item.status || 'Unknown'}</span>
            <span>{item.subtitle}</span>
            <span>{new Date(item.timestamp).toLocaleString()}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const [selectedWindow, setSelectedWindow] = useState<DashboardWindow>('7d')
  const [data, setData] = useState<DashboardOverview | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const loadOverview = useCallback(async (targetWindow: DashboardWindow) => {
    setLoading(true)
    setError('')
    try {
      const overview = await fetchDashboardOverview(targetWindow)
      setData(overview)
    } catch {
      setError('Telemetry link degraded. Showing last known dashboard frame.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadOverview(selectedWindow)
  }, [loadOverview, selectedWindow])

  const summary = data?.summary

  return (
    <div className="dashboard-page">
      <div className="dashboard-shell">
        <section className="dashboard-hero">
          <div className="dashboard-hero-content">
            <div>
              <div className="dashboard-eyebrow"><RadioTower size={14} /> Cyber Command Center</div>
              <h1 className="dashboard-title">Security Posture Dashboard</h1>
            </div>
            <div className="dashboard-hero-actions">
              {error && <Alert className="dashboard-soft-alert" type="warning" title={error} showIcon />}
              <div className="dashboard-control-panel">
                <Text className="dashboard-refresh-time">{generatedAtLabel(data?.generated_at)}</Text>
                <div className="dashboard-control-row">
                  <Segmented
                    className="dashboard-window-segmented"
                    options={windowOptions}
                    value={selectedWindow}
                    onChange={(value) => setSelectedWindow(value as DashboardWindow)}
                  />
                  <Tooltip title="Refresh">
                    <Button className="dashboard-refresh-button" icon={<ReloadOutlined />} loading={loading} onClick={() => void loadOverview(selectedWindow)} />
                  </Tooltip>
                </div>
              </div>
            </div>
          </div>
        </section>

        <div className="dashboard-posture-grid">
          <RiskPostureCard data={data} loading={loading} />
          <div className="dashboard-posture-stack">
            <div className="dashboard-grid posture-kpis">
              <MetricCard title="Open Critical Cases" value={formatNumber(summary?.open_critical_cases)} accent="#ff4d4f" sub={`${formatNumber(summary?.open_cases)} open cases`} />
              <MetricCard title="Cases In Window" value={formatNumber(summary?.total_cases)} accent="#1677ff" sub={`${selectedWindow} operating window`} />
              <MetricCard title="Critical / High Alerts" value={formatNumber(summary?.critical_high_alerts)} accent="#fa8c16" sub={`${formatNumber(summary?.total_alerts)} alerts observed`} />
              <MetricCard title="Artifacts In Scope" value={formatNumber(summary?.total_artifacts)} accent="#722ed1" sub="Distinct entities linked to alerts" />
              <MetricCard title="Automation Success" value={formatPercent(summary?.automation_success_rate)} accent="#52c41a" sub={`${formatNumber(summary?.running_playbooks)} running · ${formatNumber(summary?.failed_playbooks)} failed`} />
              <MetricCard title="Knowledge Signals" value={formatNumber(summary?.total_knowledge)} accent="#13c2c2" sub={`${formatNumber(summary?.total_enrichments)} enrichments`} />
            </div>
            <div className="dashboard-grid posture-mean-times">
              <MeanTimeCard
                title="MTTD"
                metric={data?.mean_times.mttd || { seconds: null, sample_count: 0 }}
                tooltip="Mean Time To Detect: first alert seen time to case creation."
                accent="#69b1ff"
              />
              <MeanTimeCard
                title="MTTA"
                metric={data?.mean_times.mtta || { seconds: null, sample_count: 0 }}
                tooltip="Mean Time To Acknowledge: case creation to acknowledgement."
                accent="#b37feb"
              />
              <MeanTimeCard
                title="MTTR"
                metric={data?.mean_times.mttr || { seconds: null, sample_count: 0 }}
                tooltip="Mean Time To Resolve: acknowledgement to closure."
                accent="#52c41a"
              />
            </div>
          </div>
        </div>

        <div className="dashboard-grid landscape">
          <ChartPanel title={<><PackageSearch {...lucideIconProps} /> Product Category Signals</>} compact>
            {loading && !data ? <Skeleton active paragraph={{ rows: 6 }} /> : <ProductCategorySignals data={data?.product_category_distribution || []} />}
          </ChartPanel>
          <ChartPanel title={<><GaugeIcon {...lucideIconProps} /> Severity Pressure</>} compact>
            {loading && !data ? <Skeleton active paragraph={{ rows: 6 }} /> : <SeverityPressure data={data?.severity_distribution || []} />}
          </ChartPanel>
          <ChartPanel title={<><Kanban {...lucideIconProps} /> Case Workload State</>} compact>
            {loading && !data ? <Skeleton active paragraph={{ rows: 6 }} /> : <CaseWorkloadState data={data?.case_status_mix || []} />}
          </ChartPanel>
        </div>

        <div className="dashboard-grid operations">
          <ChartPanel title={<><ChartSpline {...lucideIconProps} /> Alert Telemetry Trend</>} compact>
            {loading && !data ? <Skeleton active paragraph={{ rows: 6 }} /> : <AlertTrend data={data?.alert_trend || []} />}
          </ChartPanel>
          <ChartPanel title={<><Workflow {...lucideIconProps} /> Automation State</>}>
            {loading && !data ? <Skeleton active paragraph={{ rows: 6 }} /> : <AutomationPanel data={data?.automation || []} />}
          </ChartPanel>
          <CyberCard title={<><RadarIcon {...lucideIconProps} /> Intelligence Coverage</>}>
            {loading && !data ? <Skeleton active paragraph={{ rows: 6 }} /> : data ? <CoveragePanel data={data} /> : <CyberEmpty title="No Coverage Telemetry" />}
          </CyberCard>
        </div>

        <div className="dashboard-grid advanced">
          <ChartPanel title={<><TextSearch {...lucideIconProps} /> Threat Keyword Cloud</>} className="dashboard-keyword-card">
            {loading && !data ? <Skeleton active paragraph={{ rows: 6 }} /> : <ThreatKeywordCloud data={data?.threat_keywords || []} />}
          </ChartPanel>
          <ChartPanel title={<><RadarIcon {...lucideIconProps} /> Security Domain Radar</>}>
            {loading && !data ? <Skeleton active paragraph={{ rows: 6 }} /> : <SecurityDomainRadar data={data?.product_category_distribution || []} />}
          </ChartPanel>
          <ChartPanel title={<><Target {...lucideIconProps} /> MITRE Severity Matrix</>} className="dashboard-mitre-card">
            {loading && !data ? <Skeleton active paragraph={{ rows: 6 }} /> : <MitreSeverityMatrix data={data?.mitre_severity_heatmap || []} />}
          </ChartPanel>
        </div>

        <div className="dashboard-grid focus">
          <CyberCard title={<><ScanSearch {...lucideIconProps} /> Entity Risk Focus</>}>
            {loading && !data ? <Skeleton active paragraph={{ rows: 8 }} /> : <RiskArtifacts artifacts={data?.top_risk_artifacts || []} />}
          </CyberCard>
          <CyberCard title={<><TriangleAlert {...lucideIconProps} /> High-Severity Event Stream</>}>
            {loading && !data ? <Skeleton active paragraph={{ rows: 8 }} /> : <HighlightStream highlights={data?.recent_highlights || []} />}
          </CyberCard>
        </div>

      </div>
    </div>
  )
}
