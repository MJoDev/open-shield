// Load and stress test for open-shield.
//
//   ./scripts/load.sh smoke     ~1 minute, the pull-request gate
//   ./scripts/load.sh full      ~9 minutes, nightly
//   ./scripts/load.sh soak      30 minutes, nightly
//
// This answers the third objective of §2 of the technical document — "validate
// the system through load testing and controlled attack simulations" — and it
// answers it in a way that can fail a build, because the §8.2 budget is written
// as k6 thresholds in thresholds.js.
//
// The attack traffic is the same corpus the Go tests use (test/corpus), so a
// vector added once is exercised by the rule tests, by the end-to-end suite and
// under load, and cannot quietly stop being covered in one of the three.

import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { selectProfile } from './profiles.js';
import { thresholds, LATENCY_BUDGET_MS } from './thresholds.js';

const PROXY = (__ENV.OS_PROXY_URL || 'http://proxy').replace(/\/$/, '');
const BACKEND = (__ENV.OS_BACKEND_URL || 'http://demo-backend:3000').replace(/\/$/, '');
const PROFILE_NAME = __ENV.OS_LOAD_PROFILE || 'smoke';

const profile = selectProfile(PROFILE_NAME);

// The corpus files are read at init time, once per VU pool, not per iteration.
const attacks = JSON.parse(open('../../corpus/attacks.json')).cases;
const benign = JSON.parse(open('../../corpus/benign.json')).cases;

// Separate trends so the summary can state the overhead as a number rather than
// leaving it to be read off two tables.
const baselineLatency = new Trend('openshield_baseline_ms', true);
const proxiedLatency = new Trend('openshield_proxied_ms', true);

export const options = {
    scenarios: profile.scenarios,
    thresholds,
    // The proxy is one host; keeping connections open is what a real client
    // does, and reconnecting per iteration would measure TCP handshakes.
    noConnectionReuse: false,
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

// target builds a URL for one corpus case against a base.
function target(base, c) {
    let url = base + c.path;
    if (c.query) {
        url += '?' + c.query;
    }
    return url;
}

// request replays one corpus case. Query strings are sent exactly as the corpus
// writes them — the percent-encoding is part of the case, and several vectors
// are only detectable after the engine decodes the field.
function request(base, c) {
    const params = {
        headers: Object.assign({ 'User-Agent': 'open-shield-load/1.0' }, c.headers || {}),
        tags: { case: c.id },
    };

    if ((c.method || 'GET') === 'POST') {
        return http.post(target(base, c), c.body || '', params);
    }
    return http.request(c.method || 'GET', target(base, c), null, params);
}

function pick(list) {
    return list[Math.floor(Math.random() * list.length)];
}

// --- Scenarios ---------------------------------------------------------------

// baseline hits the protected application directly, on the same network, with
// nothing in between. Everything else is measured against this.
export function baseline() {
    const c = pick(benign);
    const res = request(BACKEND, c);

    baselineLatency.add(res.timings.duration);
    check(res, {
        'backend answered': (r) => r.status > 0 && r.status < 500,
    });
}

// proxied sends the same legitimate traffic through the whole chain: proxy →
// engine → rule chain → backend, with the audit write happening behind the
// response. The difference from baseline is the system's real cost.
export function proxied() {
    const c = pick(benign);
    const res = request(PROXY, c);

    proxiedLatency.add(res.timings.duration);
    check(res, {
        'legitimate traffic passed': (r) => r.status !== 403,
        'backend answered through the proxy': (r) => r.status > 0 && r.status < 500,
    });
}

// attack replays the corpus. The check is the point: a proxy that got fast by
// skipping the rule chain under pressure would pass every latency threshold
// and fail this one.
export function attack() {
    const c = pick(attacks);
    const res = request(PROXY, c);

    check(res, {
        'attack blocked under load': (r) => r.status === 403,
    });
}

// mixed is the shape real traffic has: mostly legitimate, with attacks
// scattered through it. It is the scenario whose latency number is worth
// quoting, because it is the one a real site would see.
export function mixed() {
    const isAttack = Math.random() < 0.05;
    const c = isAttack ? pick(attacks) : pick(benign);
    const res = request(PROXY, c);

    if (isAttack) {
        check(res, { 'attack blocked in mixed traffic': (r) => r.status === 403 });
    } else {
        check(res, { 'legitimate traffic passed in mixed traffic': (r) => r.status !== 403 });
    }
}

// --- Summary ------------------------------------------------------------------

function ms(metric, stat) {
    if (!metric || !metric.values || metric.values[stat] === undefined) {
        return null;
    }
    return metric.values[stat];
}

function fmt(value) {
    return value === null ? '   n/a' : `${value.toFixed(2)} ms`;
}

// handleSummary prints the one comparison the run exists to produce, and writes
// the raw metrics next to it so a CI job can keep them as an artifact.
export function handleSummary(data) {
    const base95 = ms(data.metrics.openshield_baseline_ms, 'p(95)');
    const proxy95 = ms(data.metrics.openshield_proxied_ms, 'p(95)');
    const base50 = ms(data.metrics.openshield_baseline_ms, 'med');
    const proxy50 = ms(data.metrics.openshield_proxied_ms, 'med');

    const overhead95 = base95 !== null && proxy95 !== null ? proxy95 - base95 : null;
    const overhead50 = base50 !== null && proxy50 !== null ? proxy50 - base50 : null;

    const lines = [
        '',
        `  open-shield · perfil de carga "${PROFILE_NAME}" — ${profile.description}`,
        '',
        '                                    p50          p95',
        `    Backend directo             ${fmt(base50).padStart(9)}   ${fmt(base95).padStart(9)}`,
        `    A través del proxy          ${fmt(proxy50).padStart(9)}   ${fmt(proxy95).padStart(9)}`,
        '    ' + '-'.repeat(52),
        `    Sobrecarga añadida          ${fmt(overhead50).padStart(9)}   ${fmt(overhead95).padStart(9)}`,
        '',
        `    Presupuesto del §8.2: < ${LATENCY_BUDGET_MS} ms de sobrecarga.`,
        '',
    ];

    if (overhead95 !== null) {
        const headroom = LATENCY_BUDGET_MS / overhead95;
        lines.push(
            overhead95 < LATENCY_BUDGET_MS
                ? `    Margen: ${headroom.toFixed(0)}× por debajo del presupuesto.`
                : `    FUERA DE PRESUPUESTO: la sobrecarga p95 supera los ${LATENCY_BUDGET_MS} ms.`,
        );
        lines.push('');
    }

    // The audit queue is the thing that degrades quietly under sustained load.
    // Its dropped counter lives on the dashboard's /api/v1/status, behind a
    // session; scripts/load.sh reads it after the run and prints it there.
    lines.push('    Revisa el contador "dropped" de la cola de auditoría tras la corrida.');
    lines.push('');

    return {
        stdout: lines.join('\n'),
        'load-summary.json': JSON.stringify(data, null, 2),
    };
}
