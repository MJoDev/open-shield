// Mirrors the JSON shapes served by dashboard/api.

export type Verdict = "allow" | "block";
export type Kind = "traffic" | "system" | "admin";

export interface AuditEntry {
  id: string;
  request_id: string;
  timestamp: string;
  kind: Kind;
  payload: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface EventsPage {
  entries: AuditEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface CountedBy {
  label: string;
  count: number;
}

export interface Bucket {
  start: string;
  allowed: number;
  blocked: number;
}

export interface Stats {
  window: string;
  total: number;
  allowed: number;
  blocked: number;
  top_ips: CountedBy[] | null;
  top_rules: CountedBy[] | null;
  series: Bucket[] | null;
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  from?: string;
  to?: string;
  broken_at?: string;
  position?: number;
  timestamp?: string;
  detail?: string;
}

export interface RuleConfig {
  name: string;
  enabled: boolean;
  config?: Record<string, unknown>;
  updated_at: string;
  updated_by?: string;
}

export interface IPRule {
  cidr: string;
  action: "allow" | "deny";
  note?: string;
  created_at?: string;
  created_by?: string;
}

/** Reads a payload field as a string, since payloads are free-form JSON. */
export function field(entry: AuditEntry, name: string): string {
  const value = entry.payload?.[name];
  if (value === undefined || value === null) return "";
  return typeof value === "string" ? value : String(value);
}

export function verdictOf(entry: AuditEntry): Verdict | "" {
  const value = field(entry, "verdict");
  return value === "allow" || value === "block" ? value : "";
}
