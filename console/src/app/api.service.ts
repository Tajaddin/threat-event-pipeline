import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Alert {
  id: string;
  ruleId: string;
  ruleTitle: string;
  severity: Severity;
  key: string;
  eventIds: string[];
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
  detectedAt: string;
  detectionLatencyMs: number;
  summary: string;
}

export interface RuleView {
  id: string;
  title: string;
  severity: Severity;
  category: string | null;
  threshold: boolean;
  hits: number;
  loadedAt: string;
  tags: string[];
}

export interface Stats {
  minutes: number;
  alerts: number;
  bySeverity: { severity: Severity; count: number }[];
  latency: { alerts: number; p50_ms: number; p95_ms: number; max_ms: number };
  rulesLoaded: number;
}

export interface GeneratorStatus {
  running: boolean;
  produced: number;
  duplicates: number;
  startedAt: string | null;
  finishedAt: string | null;
  achievedPerSecond: number;
}

export interface LagRow {
  group: string;
  topic: string;
  lag: number;
}

/** All calls go through the console's own origin: nginx (compose) or the dev proxy forward them. */
@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);

  alerts(filter: {
    severity?: string;
    ruleId?: string;
    minutes?: number;
    limit?: number;
  }): Observable<Alert[]> {
    let params = new HttpParams();
    for (const [k, v] of Object.entries(filter)) {
      if (v !== undefined && v !== null && v !== '') params = params.set(k, String(v));
    }
    return this.http.get<Alert[]>('/api/detect/alerts', { params });
  }

  rules(): Observable<{ rules: RuleView[]; errors: string[] }> {
    return this.http.get<{ rules: RuleView[]; errors: string[] }>('/api/detect/rules');
  }

  ruleYaml(id: string): Observable<string> {
    return this.http.get(`/api/detect/rules/${encodeURIComponent(id)}/yaml`, {
      responseType: 'text',
    });
  }

  reloadRules(): Observable<{ loaded: number; errors: string[] }> {
    return this.http.post<{ loaded: number; errors: string[] }>('/api/detect/rules/reload', {});
  }

  stats(minutes = 60): Observable<Stats> {
    return this.http.get<Stats>('/api/detect/stats', { params: { minutes } });
  }

  startGenerator(
    req: { eventsPerSecond: number; seconds: number; attackShare: number },
    apiKey: string,
  ): Observable<unknown> {
    return this.http.post('/api/ingest/generate', req, { headers: this.keyHeaders(apiKey) });
  }

  generatorStatus(apiKey: string): Observable<GeneratorStatus> {
    return this.http.get<GeneratorStatus>('/api/ingest/generate', {
      headers: this.keyHeaders(apiKey),
    });
  }

  private keyHeaders(apiKey: string): Record<string, string> {
    return apiKey ? { 'X-API-Key': apiKey } : {};
  }

  /** Consumer lag per group and topic from Prometheus (kafka-exporter). Empty when the observability profile is off. */
  lag(): Observable<LagRow[]> {
    const query = 'sum by (consumergroup, topic) (kafka_consumergroup_lag)';
    return this.http
      .get<{ data: { result: { metric: Record<string, string>; value: [number, string] }[] } }>(
        '/prom/api/v1/query',
        { params: { query } },
      )
      .pipe(
        map((r) =>
          r.data.result.map((x) => ({
            group: x.metric['consumergroup'] ?? '?',
            topic: x.metric['topic'] ?? '?',
            lag: Number(x.value[1]),
          })),
        ),
      );
  }

  /** Events per second through each stage, from the services' own counters. */
  rates(): Observable<{ stage: string; perSecond: number }[]> {
    const query =
      'label_replace(sum(rate(ingest_events_total{outcome="accepted"}[1m])), "stage", "ingest", "", "") or ' +
      'label_replace(sum(rate(enrich_events_total{outcome="processed"}[1m])), "stage", "enrich", "", "") or ' +
      'label_replace(sum(rate(detect_events_total{outcome="evaluated"}[1m])), "stage", "detect", "", "") or ' +
      'label_replace(sum(rate(index_documents_total{kind="event"}[1m])), "stage", "index", "", "")';
    return this.http
      .get<{ data: { result: { metric: Record<string, string>; value: [number, string] }[] } }>(
        '/prom/api/v1/query',
        { params: { query } },
      )
      .pipe(
        map((r) =>
          r.data.result.map((x) => ({
            stage: x.metric['stage'] ?? '?',
            perSecond: Number(x.value[1]),
          })),
        ),
      );
  }
}
