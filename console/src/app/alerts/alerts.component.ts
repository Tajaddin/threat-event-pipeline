import { DatePipe } from '@angular/common';
import { Component, DestroyRef, OnInit, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { interval, startWith, switchMap } from 'rxjs';
import { Alert, ApiService } from '../api.service';

@Component({
  selector: 'app-alerts',
  standalone: true,
  imports: [FormsModule, DatePipe],
  template: `
    <section class="panel">
      <header class="row">
        <h2>Alerts</h2>
        <label
          >Severity
          <select
            [(ngModel)]="severity"
            (change)="refresh()"
            aria-label="severity filter"
            data-testid="severity-filter"
          >
            <option value="">all</option>
            <option>CRITICAL</option>
            <option>HIGH</option>
            <option>MEDIUM</option>
            <option>LOW</option>
          </select>
        </label>
        <label
          >Window
          <select [(ngModel)]="minutes" (change)="refresh()" aria-label="time window">
            <option [ngValue]="15">15 min</option>
            <option [ngValue]="60">1 h</option>
            <option [ngValue]="1440">24 h</option>
            <option [ngValue]="10080">7 d</option>
          </select>
        </label>
        <span class="muted">{{ alerts().length }} shown, refreshes every 5 s</span>
      </header>
      @if (error()) {
        <p class="error" role="alert">{{ error() }}</p>
      }
      <table>
        <thead>
          <tr>
            <th>Detected</th>
            <th>Severity</th>
            <th>Rule</th>
            <th>Summary</th>
            <th>Events</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          @for (a of alerts(); track a.id) {
            <tr
              (click)="select(a)"
              [class.selected]="selected()?.id === a.id"
              data-testid="alert-row"
              [attr.data-severity]="a.severity"
            >
              <td>{{ a.detectedAt | date: 'HH:mm:ss' }}</td>
              <td>
                <span class="sev sev-{{ a.severity.toLowerCase() }}">{{ a.severity }}</span>
              </td>
              <td>{{ a.ruleId }}</td>
              <td>{{ a.summary }}</td>
              <td>{{ a.eventCount }}</td>
              <td>{{ a.detectionLatencyMs }} ms</td>
            </tr>
          } @empty {
            <tr>
              <td colspan="6" class="muted">
                No alerts in this window. Start the generator with an attack share above 0 to see
                detections.
              </td>
            </tr>
          }
        </tbody>
      </table>
      @if (selected(); as s) {
        <aside class="detail" data-testid="alert-detail">
          <h3>
            {{ s.ruleTitle }}
            <span class="sev sev-{{ s.severity.toLowerCase() }}">{{ s.severity }}</span>
          </h3>
          <dl>
            <dt>Key</dt>
            <dd>{{ s.key }}</dd>
            <dt>First / last seen</dt>
            <dd>{{ s.firstSeen | date: 'medium' }} to {{ s.lastSeen | date: 'medium' }}</dd>
            <dt>Detected</dt>
            <dd>
              {{ s.detectedAt | date: 'medium' }} ({{ s.detectionLatencyMs }} ms after ingest)
            </dd>
            <dt>Events</dt>
            <dd>{{ s.eventCount }} ({{ s.eventIds.length }} ids kept)</dd>
            <dt>Alert id</dt>
            <dd>
              <code>{{ s.id }}</code>
            </dd>
          </dl>
          <details>
            <summary>Event ids</summary>
            <ul>
              @for (id of s.eventIds; track id) {
                <li>
                  <code>{{ id }}</code>
                </li>
              }
            </ul>
          </details>
        </aside>
      }
    </section>
  `,
})
export class AlertsComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly destroyRef = inject(DestroyRef);
  severity = '';
  minutes = 60;
  readonly alerts = signal<Alert[]>([]);
  readonly selected = signal<Alert | null>(null);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    interval(5000)
      .pipe(
        startWith(0),
        switchMap(() =>
          this.api.alerts({ severity: this.severity, minutes: this.minutes, limit: 200 }),
        ),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (rows) => {
          this.alerts.set(rows);
          this.error.set(null);
        },
        error: (e) => this.error.set(`alerts unavailable: ${e.status ?? e.message}`),
      });
  }

  refresh(): void {
    this.api
      .alerts({ severity: this.severity, minutes: this.minutes, limit: 200 })
      .subscribe((rows) => this.alerts.set(rows));
  }

  select(a: Alert): void {
    this.selected.set(this.selected()?.id === a.id ? null : a);
  }
}
