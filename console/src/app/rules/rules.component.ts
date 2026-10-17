import { Component, OnInit, inject, signal } from '@angular/core';
import { ApiService, RuleView } from '../api.service';

@Component({
  selector: 'app-rules',
  standalone: true,
  template: `
    <section class="panel">
      <header class="row">
        <h2>Rules</h2>
        <button (click)="reload()" [disabled]="busy()" data-testid="reload-rules">
          Reload from disk
        </button>
        <span class="muted">{{ rules().length }} loaded</span>
      </header>
      @if (message()) {
        <p class="muted">{{ message() }}</p>
      }
      @for (e of errors(); track e) {
        <p class="error">{{ e }}</p>
      }
      <table>
        <thead>
          <tr>
            <th>Id</th>
            <th>Title</th>
            <th>Severity</th>
            <th>Type</th>
            <th>Hits</th>
            <th>Tags</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          @for (r of rules(); track r.id) {
            <tr data-testid="rule-row">
              <td>
                <code>{{ r.id }}</code>
              </td>
              <td>{{ r.title }}</td>
              <td>
                <span class="sev sev-{{ r.severity.toLowerCase() }}">{{ r.severity }}</span>
              </td>
              <td>{{ r.threshold ? 'threshold' : 'stateless' }}</td>
              <td data-testid="rule-hits">{{ r.hits }}</td>
              <td class="muted">{{ r.tags.join(', ') }}</td>
              <td><button class="link" (click)="show(r)">yaml</button></td>
            </tr>
          }
        </tbody>
      </table>
      @if (yaml(); as y) {
        <pre class="yaml" data-testid="rule-yaml">{{ y }}</pre>
      }
    </section>
  `,
})
export class RulesComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly rules = signal<RuleView[]>([]);
  readonly errors = signal<string[]>([]);
  readonly yaml = signal<string | null>(null);
  readonly message = signal<string | null>(null);
  readonly busy = signal(false);

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.rules().subscribe((r) => {
      this.rules.set(r.rules);
      this.errors.set(r.errors);
    });
  }

  reload(): void {
    this.busy.set(true);
    this.api.reloadRules().subscribe({
      next: (r) => {
        this.message.set(`reloaded ${r.loaded} rules`);
        this.busy.set(false);
        this.load();
      },
      error: (e) => {
        this.message.set(`reload failed: ${e.status ?? e.message}`);
        this.busy.set(false);
      },
    });
  }

  show(r: RuleView): void {
    this.api.ruleYaml(r.id).subscribe((y) => this.yaml.set(y));
  }
}
