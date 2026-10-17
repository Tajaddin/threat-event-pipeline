import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { ApiService } from './api.service';
import { App } from './app';

describe('App', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [
        provideZonelessChangeDetection(),
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    }).compileComponents();
  });

  it('renders the title and the three tabs', async () => {
    const fixture = TestBed.createComponent(App);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('h1')?.textContent).toContain('Threat event console');
    expect(el.querySelectorAll('nav button').length).toBe(3);
  });

  it('switches tabs', async () => {
    const fixture = TestBed.createComponent(App);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    (el.querySelector('[data-testid="tab-rules"]') as HTMLButtonElement).click();
    await fixture.whenStable();
    expect(el.querySelector('app-rules')).toBeTruthy();
    expect(el.querySelector('app-alerts')).toBeFalsy();
  });
});

describe('ApiService', () => {
  it('maps Prometheus lag vectors to rows', () => {
    TestBed.configureTestingModule({
      providers: [
        provideZonelessChangeDetection(),
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });
    const api = TestBed.inject(ApiService);
    const http = TestBed.inject(HttpTestingController);
    let rows: { group: string; topic: string; lag: number }[] = [];
    api.lag().subscribe((r) => (rows = r));
    const req = http.expectOne((r) => r.url === '/prom/api/v1/query');
    req.flush({
      data: {
        result: [
          { metric: { consumergroup: 'detect', topic: 'events.enriched' }, value: [0, '1234'] },
        ],
      },
    });
    expect(rows).toEqual([{ group: 'detect', topic: 'events.enriched', lag: 1234 }]);
    http.verify();
  });
});
