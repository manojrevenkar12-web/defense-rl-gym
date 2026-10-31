import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mistake } from '../features/graders/GraderMatrix';
import { boardFor, isResults, type Results } from '../shared/lib/results';
import { App } from './App';
import fixture from './fixture.json';

const results = fixture as unknown as Results;

function mockFetch(impl: () => Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn(impl));
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('App', () => {
  it('shows a loading state, then every section', async () => {
    mockFetch(async () => new Response(JSON.stringify(results)));
    render(<App />);
    expect(screen.getByRole('status', { name: 'Loading results' })).toBeTruthy();
    for (const name of [
      'Which patching reward pays only for real fixes?',
      'Patches written by someone who never saw the grader',
      'What a learned policy does with each reward',
      'Release gate',
    ]) {
      expect(await screen.findByRole('heading', { level: 2, name })).toBeTruthy();
    }
  });

  it('shows an error with a working retry', async () => {
    let calls = 0;
    mockFetch(async () => {
      calls += 1;
      return calls === 1 ? new Response('oops', { status: 500 }) : new Response(JSON.stringify(results));
    });
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { level: 2, name: 'Release gate' })).toBeTruthy();
    expect(calls).toBe(2);
  });

  it('shows an empty state when no results were generated', async () => {
    mockFetch(async () => new Response('', { status: 404 }));
    render(<App />);
    expect(await screen.findByText('No results yet')).toBeTruthy();
  });

  it('rejects a file that is not results', async () => {
    mockFetch(async () => new Response(JSON.stringify({ hello: 1 })));
    render(<App />);
    expect(await screen.findByText(/not in the expected format/)).toBeTruthy();
  });

  it('switches the network on the policy board', async () => {
    mockFetch(async () => new Response(JSON.stringify(results)));
    render(<App />);
    const blind = await screen.findByRole('button', { name: 'Held-out (blind)' });
    fireEvent.click(blind);
    expect(blind.getAttribute('aria-pressed')).toBe('true');
    expect(screen.getByText(/Written blind from a one-page brief/)).toBeTruthy();
  });
});

describe('results helpers', () => {
  it('recognises the fixture', () => {
    expect(isResults(results)).toBe(true);
    expect(isResults(null)).toBe(false);
  });

  it('lists trained policies before baselines on a board', () => {
    const fam = results.rl!.families[0]!;
    const keys = boardFor(results, fam).map((x) => x.key);
    expect(keys.indexOf('robust_clone')).toBeLessThan(keys.indexOf('analyst'));
    expect(boardFor(results, 'heldout').length).toBeGreaterThan(0);
    expect(boardFor(results, 'nowhere')).toEqual([]);
  });

  it('colours a grader cell by what kind of mistake it is', () => {
    expect(mistake('ref', 1)).toEqual({ kind: 'right', size: 0 });
    expect(mistake('ref', 0.4).kind).toBe('withheld');
    expect(mistake('hack_public', 0.7)).toEqual({ kind: 'unearned', size: 0.7 });
    expect(mistake('partial', 0).kind).toBe('right');
  });
});
