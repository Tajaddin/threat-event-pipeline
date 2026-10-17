import { expect, test } from '@playwright/test';

// Runs against the compose stack: the console on CONSOLE_BASE proxies to detect-service and ingest-service.
test('generator burst with attacks produces alerts visible in the console', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Threat event console' })).toBeVisible();

  await page.getByTestId('tab-pipeline').click();
  if (process.env['INGEST_API_KEY']) {
    await page.getByTestId('gen-key').fill(process.env['INGEST_API_KEY']);
  }
  await page.getByTestId('gen-rate').fill('300');
  await page.getByTestId('gen-seconds').fill('8');
  await page.getByTestId('gen-attack').fill('1');
  await page.getByTestId('gen-start').click();
  await expect(page.getByTestId('gen-status')).toContainText('produced', { timeout: 30_000 });

  await page.getByTestId('tab-alerts').click();
  await expect(page.getByTestId('alert-row').first()).toBeVisible({ timeout: 120_000 });
  await page.getByTestId('alert-row').first().click();
  await expect(page.getByTestId('alert-detail')).toContainText('Alert id');

  await page.getByTestId('severity-filter').selectOption('HIGH');
  await expect(page.getByTestId('alert-row').first()).toHaveAttribute('data-severity', 'HIGH', {
    timeout: 30_000,
  });

  await page.getByTestId('tab-rules').click();
  await expect(page.getByTestId('rule-row')).toHaveCount(7, { timeout: 30_000 });
  const hits = await page.getByTestId('rule-hits').allTextContents();
  expect(hits.some((h) => Number(h) > 0)).toBeTruthy();
});
