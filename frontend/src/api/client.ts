import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export const apiClient = axios.create({ baseURL: API_URL });

// Token is kept in localStorage for simplicity in this foundation phase.
// Known trade-off: localStorage is readable by any JS on the page, so it
// is more XSS-exposed than an httpOnly cookie. Acceptable for a local
// graduation-project demo; documented here rather than silently assumed.
const TOKEN_KEY = "siem_access_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

apiClient.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

/**
 * The WebSocket URL for the live stream, derived from the same base URL
 * as the REST calls so a deployment only has to configure VITE_API_URL
 * once (http -> ws, https -> wss). A relative VITE_API_URL falls back to
 * the page's own origin.
 */
export function streamUrl(token: string): string {
  const base = new URL(API_URL, window.location.origin);
  base.protocol = base.protocol === "https:" ? "wss:" : "ws:";
  base.pathname = "/ws/stream";
  base.search = `?token=${encodeURIComponent(token)}`;
  return base.toString();
}

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "investigating" | "resolved" | "false_positive";
export type UserRole = "administrator" | "security_analyst";

export interface LoginResponse {
  access_token: string;
  token_type: string;
  username: string;
  role: UserRole;
}

// v2.3 — the /api/auth/login response is now union-shaped: either a full
// token (no MFA) or an MFA challenge. See backend app/schemas/auth.py.
export interface LoginResult {
  mfa_required: boolean;
  enrollment_required: boolean;
  mfa_token: string | null;
  access_token: string | null;
  token_type: string;
  username: string | null;
  role: UserRole | null;
}

export interface MfaStatus {
  status: "disabled" | "pending" | "active";
  enabled_globally: boolean;
  required_globally: boolean;
  backup_codes_remaining: number;
  confirmed_at: string | null;
}

export interface MfaEnrollResponse {
  secret: string;
  otpauth_uri: string;
  issuer: string;
  account: string;
  note: string;
}

export interface DashboardStats {
  total_events: number;
  events_today: number;
  active_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  monitored_endpoints: number;
  online_endpoints: number;
  detection_rate: number | null;
  avg_detection_time_seconds: number | null;
  soar_actions: number;
  soar_actions_today: number;
}

export interface Alert {
  id: number;
  timestamp: string;
  severity: Severity;
  status: AlertStatus;
  source_ip: string | null;
  destination_ip: string | null;
  rule_id: number;
  rule_name: string | null;
  rule_type: string | null;
  mitre_id: string | null;
  kill_chain_phase: string | null;
  description: string;
  log_id: number | null;
  incident_id: number | null;
  created_at: string | null;
}

export interface LogEvent {
  id: number;
  timestamp: string;
  hostname: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  username: string | null;
  event_type: string;
  event_id: number | null;
  severity: Severity;
  source: string;
  operating_system: string | null;
  raw_log: string;
  normalized_data: Record<string, unknown> | null;
  agent_id: number | null;
}

export interface AlertStatusChange {
  previous_status: AlertStatus | null;
  new_status: AlertStatus;
  changed_by: string | null;
  changed_at: string | null;
}

export interface AlertDetail extends Alert {
  rule_description: string | null;
  rule_threshold: number | null;
  rule_time_window_seconds: number | null;
  triggering_log: LogEvent | null;
  related_logs: LogEvent[];
  status_history: AlertStatusChange[];
}

export interface DetectionRule {
  id: number;
  name: string;
  description: string;
  rule_type: string;
  threshold: number;
  time_window_seconds: number;
  severity: Severity;
  mitre_id: string | null;
  kill_chain_phase: string | null;
  parameters: Record<string, unknown> | null;
  enabled: boolean;
  implemented: boolean;
}

export interface SoarAction {
  id: number;
  timestamp: string | null;
  action_type: string;
  target: string;
  alert_id: number | null;
  rule_name: string | null;
  status: "simulated" | "pending" | "executed" | "failed";
  detail: string | null;
  execution_requested: boolean;
}

export interface SoarActionsResponse {
  total: number;
  enabled: boolean;
  execution_mode: "record_only" | "execute_requested";
  items: SoarAction[];
}

export interface EndpointRow {
  source: "local" | "wazuh";
  agent_id: string | null;
  hostname: string | null;
  ip_address: string | null;
  operating_system: string | null;
  status: string | null;
  last_seen: string | null;
  version: string | null;
}

export interface WazuhStatus {
  status: "not_configured" | "connected" | "unreachable" | "unauthorized" | "error";
  url: string | null;
  detail: string;
  agent_count: number | null;
}

export interface EndpointsOverview {
  total: number;
  sources: { local: number; wazuh: number };
  wazuh_integration: WazuhStatus;
  items: EndpointRow[];
}

export interface Scenario {
  key: string;
  name: string;
  description: string;
  expected_rules: string[];
  event_count: number;
  estimated_seconds: number;
}

export interface HealthReport {
  api: string;
  database: string;
  detection_engine: string;
  detection_rules_implemented: string[];
  detection_rules_enabled_without_handler: string[];
  collector: string;
  websocket: string;
  websocket_subscribers: number;
  soar: string;
  wazuh: string;
}

export interface MitreCoverageRow {
  rule_id: number;
  rule_name: string;
  rule_type: string;
  mitre_id: string | null;
  kill_chain_phase: string | null;
  severity: Severity;
  enabled: boolean;
  alerts: number;
}

export interface TimelineBucket {
  hour: string;
  events: number;
  alerts: number;
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

export async function login(username: string, password: string): Promise<LoginResult> {
  const response = await apiClient.post<LoginResult>("/api/auth/login", { username, password });
  return response.data;
}

/** Step 2 of login: exchange the MFA challenge token + code for a token. */
export async function mfaVerify(mfaToken: string, code: string): Promise<LoginResponse> {
  const response = await apiClient.post<LoginResponse>("/api/auth/mfa/verify", {
    mfa_token: mfaToken,
    code,
  });
  return response.data;
}

// ─── MFA enrolment / management ──────────────────────────────────────
export async function fetchMfaStatus(): Promise<MfaStatus> {
  const response = await apiClient.get<MfaStatus>("/api/mfa/status");
  return response.data;
}

export async function mfaEnroll(): Promise<MfaEnrollResponse> {
  const response = await apiClient.post<MfaEnrollResponse>("/api/mfa/enroll", {});
  return response.data;
}

export async function mfaConfirm(code: string): Promise<{ status: string; backup_codes: string[]; note: string }> {
  const response = await apiClient.post("/api/mfa/confirm", { code });
  return response.data;
}

export async function mfaDisable(code: string): Promise<{ ok: boolean; detail: string }> {
  const response = await apiClient.post("/api/mfa/disable", { code });
  return response.data;
}

export async function fetchHealth(): Promise<HealthReport> {
  // The only unauthenticated endpoint -- used by the login screen to say
  // whether the backend is even reachable before blaming the password.
  const response = await apiClient.get<HealthReport>("/health");
  return response.data;
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const response = await apiClient.get<DashboardStats>("/api/dashboard/stats");
  return response.data;
}

export async function fetchSeverityDistribution(): Promise<{
  counts: Record<Severity, number>;
  total: number;
}> {
  const response = await apiClient.get("/api/dashboard/severity-distribution");
  return response.data;
}

export async function fetchTimeline(hours = 24): Promise<TimelineBucket[]> {
  const response = await apiClient.get("/api/dashboard/timeline", { params: { hours } });
  return response.data.buckets;
}

export async function fetchTopSources(limit = 5): Promise<{ source_ip: string; alerts: number }[]> {
  const response = await apiClient.get("/api/dashboard/top-sources", { params: { limit } });
  return response.data;
}

export async function fetchMitreCoverage(): Promise<MitreCoverageRow[]> {
  const response = await apiClient.get<MitreCoverageRow[]>("/api/dashboard/mitre-coverage");
  return response.data;
}

export interface AlertQuery {
  severity?: Severity;
  status?: AlertStatus;
  source_ip?: string;
  rule_id?: number;
  since_hours?: number;
  limit?: number;
  offset?: number;
}

export async function fetchAlerts(query: AlertQuery = {}): Promise<{ total: number; items: Alert[] }> {
  const response = await apiClient.get("/api/alerts", { params: query });
  return response.data;
}

/**
 * Download the current alerts filter view as a CSV file. Reuses every
 * filter the caller would use for {@link fetchAlerts} so the export
 * lines up with what the operator sees on screen — see the backend
 * contract in `app/api/routes/alerts.py::_ALERT_CSV_COLUMNS`.
 */
export async function exportAlertsCsv(query: AlertQuery = {}): Promise<void> {
  const response = await apiClient.get("/api/alerts", {
    params: { ...query, format: "csv" },
    responseType: "blob",
  });
  triggerCsvDownload(response.data as Blob, response.headers, "aegisiq_alerts.csv");
}

export async function fetchAlert(id: number): Promise<AlertDetail> {
  const response = await apiClient.get<AlertDetail>(`/api/alerts/${id}`);
  return response.data;
}

export async function updateAlertStatus(id: number, status: AlertStatus): Promise<Alert> {
  const response = await apiClient.patch<Alert>(`/api/alerts/${id}/status`, { status });
  return response.data;
}

export async function deleteAlert(id: number): Promise<void> {
  await apiClient.delete(`/api/alerts/${id}`);
}

export async function bulkDeleteAlerts(ids: number[]): Promise<{ deleted: number }> {
  const response = await apiClient.post<{ deleted: number }>(`/api/alerts/bulk-delete`, { ids });
  return response.data;
}

export async function deleteLog(id: number): Promise<void> {
  await apiClient.delete(`/api/logs/${id}`);
}

export async function bulkDeleteLogs(ids: number[]): Promise<{ deleted: number }> {
  const response = await apiClient.post<{ deleted: number }>(`/api/logs/bulk-delete`, { ids });
  return response.data;
}

// ---------------------------------------------------------------------------
// Retention (memory cleanup)
// ---------------------------------------------------------------------------

export interface RetentionConfig {
  log_retention_days: number;
  alert_retention_days: number;
  max_db_size_mb: number;
}

export interface PurgeRequest {
  alerts_older_than_days?: number;
  logs_older_than_days?: number;
  only_triaged_alerts?: boolean;
  min_severity_to_keep?: Severity | null;
}

export interface PurgeResponse {
  deleted_alerts: number;
  deleted_logs: number;
  deleted_soar_actions: number;
  deleted_alert_status_history: number;
  cutoff_alerts: string | null;
  cutoff_logs: string | null;
  detail: string;
}

export interface PurgeDryRun {
  would_delete_alerts: number;
  would_delete_logs: number;
  cutoff_alerts?: string;
  cutoff_logs?: string;
}

export async function fetchRetentionConfig(): Promise<RetentionConfig> {
  const response = await apiClient.get<RetentionConfig>("/api/retention/config");
  return response.data;
}

export async function purgeRetention(payload: PurgeRequest): Promise<PurgeResponse> {
  const response = await apiClient.post<PurgeResponse>("/api/retention/purge", payload);
  return response.data;
}

export async function purgeDryRun(payload: PurgeRequest): Promise<PurgeDryRun> {
  const response = await apiClient.post<PurgeDryRun>("/api/retention/dry-run", payload);
  return response.data;
}

// ---------------------------------------------------------------------------
// v2.0 — Audit log
// ---------------------------------------------------------------------------

export interface AuditEntry {
  id: number;
  timestamp: string | null;
  username: string | null;
  action: string;
  target: string | null;
  outcome: "success" | "failure" | string;
  source_ip: string | null;
  details: Record<string, unknown> | null;
}

export interface AuditQuery {
  username?: string;
  action?: string;
  outcome?: string;
  since_hours?: number;
  limit?: number;
  offset?: number;
}

export async function fetchAuditEntries(query: AuditQuery = {}): Promise<{ total: number; items: AuditEntry[] }> {
  const response = await apiClient.get("/api/audit", { params: query });
  return response.data;
}

// ---------------------------------------------------------------------------
// v2.0 — Password change (self-service)
// ---------------------------------------------------------------------------

export interface PasswordChangeRequest {
  current_password: string;
  new_password: string;
}

export interface PasswordChangeResponse {
  ok: boolean;
  detail: string;
  policy_errors: string[];
}

export interface PasswordPolicy {
  min_length: number;
  min_categories: number;
  categories: string[];
  requirements: string[];
}

export async function changePassword(payload: PasswordChangeRequest): Promise<PasswordChangeResponse> {
  const response = await apiClient.patch<PasswordChangeResponse>("/api/auth/password", payload);
  return response.data;
}

export async function fetchPasswordPolicy(): Promise<PasswordPolicy> {
  const response = await apiClient.get<PasswordPolicy>("/api/auth/policy");
  return response.data;
}

// ---------------------------------------------------------------------------
// v2.1 — Log Analysis Report (premium)
// ---------------------------------------------------------------------------

export interface LicenseStatus {
  active: boolean;
  tier: "free" | "trial" | "educational" | "business" | "enterprise";
  features: string[];
  key_masked: string | null;
  detail: string;
}

export interface AnalysisFinding {
  rule: string;
  rule_type: string;
  mitre: string | null;
  mitre_blurb?: string;
  kill_chain: string | null;
  severity: "low" | "medium" | "high" | "critical";
  source: string;
  count: number;
  reason: string;
  // v2.2 enrichment
  first_seen?: string | null;
  last_seen?: string | null;
  sample_events?: string[];
  targeted_usernames?: string[];
  scanned_ports?: number[];
  compromised_account?: string | null;
  matched_pattern?: string;
  command?: string | null;
  pattern?: string;
  cwe_owasp?: string[];
  ua_signature?: string;
}

export interface AnalysisRecommendation {
  finding: string;
  action: string;
  priority: "low" | "medium" | "high" | "critical";
  steps?: string[];
  mitre?: string | null;
}

export interface AnalysisIocs {
  source_ips?: [string, number][];
  usernames?: [string, number][];
  hostnames?: [string, number][];
  ports?: [number, number][];
  urls?: [string, number][];
  user_agents?: [string, number][];
}

export interface AnalysisTimelineBucket {
  hour: string;
  total: number;
  by_severity: Record<string, number>;
}

export interface AnalysisSummary {
  generated_at: string;
  elapsed_ms: number;
  input_format: string;
  truncated: boolean;
  total_bytes: number;
  total_lines: number;
  parsed_events: number;
  unparsed_events: number;
  parse_errors: number;
  worst_severity: string | null;
  event_type_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  top_sources: [string, number][];
  top_users: [string, number][];
  findings_count: number;
  findings_by_severity: Record<string, number>;
  findings_by_rule: Record<string, number>;
  findings: AnalysisFinding[];
  recommendations: AnalysisRecommendation[];
  first_event_ts: string | null;
  last_event_ts: string | null;
  // v2.2 enrichment
  iocs?: AnalysisIocs;
  timeline?: AnalysisTimelineBucket[];
}

export interface AnalysisReport {
  id: number;
  filename: string;
  status: "pending" | "running" | "complete" | "failed";
  total_bytes: number;
  created_at: string | null;
  finished_at: string | null;
  license_tier: string | null;
  error: string | null;
  summary?: AnalysisSummary;
  // Brief-list only:
  findings_count?: number;
  worst_severity?: string | null;
  parsed_events?: number;
}

export async function fetchLicenseStatus(): Promise<LicenseStatus> {
  const response = await apiClient.get<LicenseStatus>("/api/license/status");
  return response.data;
}

export async function activateLicense(key: string): Promise<LicenseStatus> {
  const response = await apiClient.patch<LicenseStatus>("/api/license/activate", { key });
  return response.data;
}

export async function uploadAnalysisFile(file: File): Promise<AnalysisReport> {
  const fd = new FormData();
  fd.append("file", file);
  const response = await apiClient.post<AnalysisReport>("/api/analysis/upload", fd, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return response.data;
}

export async function fetchAnalysisReports(): Promise<{ total: number; items: AnalysisReport[] }> {
  const response = await apiClient.get("/api/analysis");
  return response.data;
}

export async function fetchAnalysisReport(id: number): Promise<AnalysisReport> {
  const response = await apiClient.get<AnalysisReport>(`/api/analysis/${id}`);
  return response.data;
}

export async function deleteAnalysisReport(id: number): Promise<void> {
  await apiClient.delete(`/api/analysis/${id}`);
}

/**
 * Open the printable HTML report in a new tab.
 *
 * BUGFIX (v2.2): the previous flow used `window.open(url)` on the
 * `/api/analysis/:id/download` endpoint. Browsers do NOT send the
 * Authorization header on a plain window.open() navigation, so the
 * endpoint returned 401 and the new tab appeared blank. This helper
 * fetches the HTML through the authenticated axios client, wraps it
 * in a same-origin blob URL, and opens THAT — the blob comes with the
 * report already downloaded, so the new tab is guaranteed to render.
 */
export async function openAnalysisReport(id: number): Promise<void> {
  const response = await apiClient.get(`/api/analysis/${id}/download`, {
    responseType: "blob",
  });
  const blob = new Blob([response.data as BlobPart], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const w = window.open(url, "_blank", "noopener,noreferrer");
  if (!w) {
    // Popup blocked — fall back to a download link so the user can still get the file.
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegisiq_report_${id}.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  // Free the blob after 60 s — plenty of time for the browser to load it.
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

export interface LogQuery {
  severity?: Severity;
  event_type?: string;
  source_ip?: string;
  hostname?: string;
  username?: string;
  search?: string;
  since_hours?: number;
  limit?: number;
  offset?: number;
}

export async function fetchLogs(query: LogQuery = {}): Promise<{ total: number; items: LogEvent[] }> {
  const response = await apiClient.get("/api/logs", { params: query });
  return response.data;
}

/**
 * Download the current logs filter view as a CSV file. Same filter
 * contract as {@link fetchLogs}. Backend column contract lives in
 * `app/api/routes/logs.py::_LOG_CSV_COLUMNS`.
 */
export async function exportLogsCsv(query: LogQuery = {}): Promise<void> {
  const response = await apiClient.get("/api/logs", {
    params: { ...query, format: "csv" },
    responseType: "blob",
  });
  triggerCsvDownload(response.data as Blob, response.headers, "aegisiq_logs.csv");
}

/**
 * Small helper: browsers refuse to open text/csv inline, so we prefer
 * the standard "create anchor + click" download flow. Uses the server's
 * `Content-Disposition` filename when present (dated), otherwise the
 * fallback the caller supplied.
 */
function triggerCsvDownload(blob: Blob, headers: unknown, fallback: string): void {
  const disposition = ((headers as Record<string, string>)["content-disposition"] ?? "") as string;
  const match = /filename="?([^"]+)"?/.exec(disposition);
  const filename = match?.[1] ?? fallback;

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export async function fetchEventTypes(): Promise<string[]> {
  const response = await apiClient.get<string[]>("/api/logs/event-types");
  return response.data;
}

export async function fetchRules(): Promise<DetectionRule[]> {
  const response = await apiClient.get<DetectionRule[]>("/api/rules");
  return response.data;
}

export async function updateRule(
  id: number,
  changes: Partial<Pick<DetectionRule, "threshold" | "time_window_seconds" | "severity" | "enabled">>
): Promise<DetectionRule> {
  const response = await apiClient.patch<DetectionRule>(`/api/rules/${id}`, changes);
  return response.data;
}

export async function fetchSoarActions(limit = 100): Promise<SoarActionsResponse> {
  const response = await apiClient.get<SoarActionsResponse>("/api/soar/actions", {
    params: { limit },
  });
  return response.data;
}

export async function fetchEndpoints(): Promise<EndpointsOverview> {
  const response = await apiClient.get<EndpointsOverview>("/api/agents/overview");
  return response.data;
}

export async function fetchWazuhStatus(): Promise<WazuhStatus> {
  const response = await apiClient.get<WazuhStatus>("/api/integrations/wazuh/status");
  return response.data;
}

export async function fetchScenarios(): Promise<Scenario[]> {
  const response = await apiClient.get<Scenario[]>("/api/simulation/scenarios");
  return response.data;
}

export interface ScenarioRunResponse {
  status: string;
  scenario: string;
  name: string;
  event_count: number;
  estimated_seconds: number;
  expected_rules: string[];
  detail: string;
}

export async function runScenario(key: string): Promise<ScenarioRunResponse> {
  const response = await apiClient.post<ScenarioRunResponse>(`/api/simulation/run/${key}`);
  return response.data;
}
