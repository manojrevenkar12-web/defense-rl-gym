import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

test('every section renders from the generated results, without console errors', async ({ page }) => {
  const errors: string[] = [];
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('tested against the ways to game them');
  for (const name of [
    'Which patching reward pays only for real fixes?',
    'Patches written by someone who never saw the grader',
    'What a learned policy does with each reward',
    'Throughput on one core',
    'Release gate',
  ]) {
    await expect(page.getByRole('heading', { level: 2, name })).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test('switching the network redraws the policy board', async ({ page }) => {
  await page.goto('/');
  const board = page.getByRole('region', { name: /^Policies on the/ });
  const before = await board.textContent();
  await page.getByRole('button', { name: 'Held-out (blind)' }).click();
  await expect(board).not.toHaveText(before ?? '');
});

test('nothing scrolls sideways on a phone', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 2, name: 'Release gate' })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

test('no serious accessibility violations', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 2, name: 'Release gate' })).toBeVisible();
  const a = await new AxeBuilder({ page } as unknown as ConstructorParameters<typeof AxeBuilder>[0])
    .withTags(['wcag2a', 'wcag2aa'])
    .analyze();
  expect(a.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
});
