import { Component, signal } from '@angular/core';
import { AlertsComponent } from './alerts/alerts.component';
import { PipelineComponent } from './pipeline/pipeline.component';
import { RulesComponent } from './rules/rules.component';

type Tab = 'alerts' | 'rules' | 'pipeline';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [AlertsComponent, RulesComponent, PipelineComponent],
  template: `
    <main class="app">
      <header class="top">
        <h1>Threat event console</h1>
        <nav>
          @for (t of tabs; track t) {
            <button
              [class.active]="tab() === t"
              (click)="tab.set(t)"
              [attr.data-testid]="'tab-' + t"
            >
              {{ t }}
            </button>
          }
        </nav>
      </header>
      @switch (tab()) {
        @case ('alerts') {
          <app-alerts />
        }
        @case ('rules') {
          <app-rules />
        }
        @case ('pipeline') {
          <app-pipeline />
        }
      }
    </main>
  `,
})
export class App {
  readonly tabs: Tab[] = ['alerts', 'rules', 'pipeline'];
  readonly tab = signal<Tab>('alerts');
}
