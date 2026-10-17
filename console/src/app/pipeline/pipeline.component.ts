import { DecimalPipe } from '@angular/common';
import { Component, DestroyRef, OnInit, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { catchError, interval, of, startWith, switchMap } from 'rxjs';
import { ApiService, GeneratorStatus, LagRow, Stats } from '../api.service';

@Component({
  selector: 'app-pipeline',
  standalone: true,
  imports: [FormsModule, DecimalPipe],
  template: `
    <section class="panel">
      <header class="row">
        <h2>Pipeline</h2>
        <span class="muted">refreshes every 5 s</span>
      </header>
      <div class="cards">
        <div class="card">
          <span class="label">alerts, last hour</span
          ><strong data-testid="stat-alerts">{{ stats()?.alerts ?? '-' }}</strong>
        </div>
        <div class="card">
          <span class="label">detection latency p95</span
          ><strong>{{ stats()?.latency?.p95_ms | number: '1.0-0' }} ms</strong>
        </div>
        <div class="card">
          <span class="label">rules loaded</span><strong>{{ stats()?.rulesLoaded ?? '-' }}</strong>
        </div>
        @for (r of rates(); track r.stage) {
          <div class="card">
            <span class="label">{{ r.stage }} events/s</span
            ><strong>{{ r.perSecond | number: '1.0-0' }}</strong>
          </div>
        }
      </div>
      <h3>Consumer lag</h3>
      @if (lag().length === 0) {
        <p class="muted">
          No lag data: start the observability profile (Prometheus + kafka-exporter).
        </p>
      }
      <table>
        <thead>
          <tr>
            <th>Group</th>
            <th>Topic</th>
            <th>Lag</th>
          </tr>
        </thead>
        <tbody>
          @for (l of lag(); track l.group + l.topic) {
            <tr [class.warn]="l.lag > 50000">
              <td>{{ l.group }}</td>
              <td>{{ l.topic }}</td>
              <td>{{ l.lag | number }}</td>
            </tr>
          }
        </tbody>
      </table>
    </section>

    <section class="panel">
      <header class="row"><h2>Synthetic traffic</h2></header>
      <form class="row" (ngSubmit)="start()">
        <label
          >events/s
          <input
            type="number"
            [(ngModel)]="rate"
            name="rate"
            min="1"
            max="50000"
            data-testid="gen-rate"
        /></label>
        <label
          >seconds
          <input
            type="number"
            [(ngModel)]="seconds"
            name="seconds"
            min="1"
            max="3600"
            data-testid="gen-seconds"
        /></label>
        <label
          >attack share
          <input
            type="number"
            [(ngModel)]="attackShare"
            name="attackShare"
            min="0"
            max="1"
            step="0.05"
            data-testid="gen-attack"
        /></label>
        <label
          >API key
          <input
            type="password"
            [(ngModel)]="apiKey"
            name="apiKey"
            placeholder="if the ingest API requires one"
            data-testid="gen-key"
        /></label>
        <button type="submit" [disabled]="status()?.running" data-testid="gen-start">Start</button>
      </form>
      @if (genError()) {
        <p class="error" role="alert">{{ genError() }}</p>
      }
      @if (status(); as s) {
        <p data-testid="gen-status">
          {{ s.running ? 'running' : 'idle' }}: {{ s.produced | number }} produced,
          {{ s.duplicates | number }} duplicates,
          {{ s.achievedPerSecond | number: '1.0-0' }} events/s achieved
        </p>
      }
    </section>
  `,
})
export class PipelineComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly destroyRef = inject(DestroyRef);
  readonly stats = signal<Stats | null>(null);
  readonly lag = signal<LagRow[]>([]);
  readonly rates = signal<{ stage: string; perSecond: number }[]>([]);
  readonly status = signal<GeneratorStatus | null>(null);
  readonly genError = signal<string | null>(null);
  rate = 500;
  seconds = 30;
  attackShare = 0.05;
  apiKey = '';

  ngOnInit(): void {
    interval(5000)
      .pipe(
        startWith(0),
        switchMap(() => this.api.stats(60).pipe(catchError(() => of(null)))),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe((s) => this.stats.set(s));
    interval(5000)
      .pipe(
        startWith(0),
        switchMap(() => this.api.lag().pipe(catchError(() => of([] as LagRow[])))),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe((l) => this.lag.set(l));
    interval(5000)
      .pipe(
        startWith(0),
        switchMap(() => this.api.rates().pipe(catchError(() => of([])))),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe((r) => this.rates.set(r));
    interval(2000)
      .pipe(
        startWith(0),
        switchMap(() => this.api.generatorStatus(this.apiKey).pipe(catchError(() => of(null)))),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe((s) => this.status.set(s));
  }

  start(): void {
    this.genError.set(null);
    this.api
      .startGenerator(
        { eventsPerSecond: this.rate, seconds: this.seconds, attackShare: this.attackShare },
        this.apiKey,
      )
      .subscribe({
        error: (e) => this.genError.set(`could not start: ${e.status ?? e.message}`),
      });
  }
}
