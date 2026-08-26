// Load profiles. Pick one with OS_LOAD_PROFILE; scripts/load.sh does that.
//
// The four scenarios run one after another rather than together, and that is
// the whole point of the file. `baseline` measures the backend on its own and
// `proxied` measures the same requests through the proxy; the difference
// between them is the number §8.2 budgets at under 50 ms. Run concurrently they
// would be competing for the same CPU, and the difference would be measuring
// the contention rather than the system.

const SECOND = 1;

// stage builds one sequential scenario. Each starts where the previous ended,
// with a small gap so the rate-limit counters and connection pools of one do
// not bleed into the next.
function stage(exec, startTime, duration, rate, preAllocatedVUs) {
    return {
        executor: 'constant-arrival-rate',
        exec,
        startTime: `${startTime}s`,
        duration: `${duration}s`,
        // A fixed arrival rate rather than a fixed number of VUs: latency under
        // a known offered load is the question. With fixed VUs the load falls
        // as latency rises, which hides exactly the degradation being looked
        // for.
        rate,
        timeUnit: '1s',
        preAllocatedVUs,
        maxVUs: preAllocatedVUs * 4,
        tags: { scenario: exec },
        gracefulStop: '5s',
    };
}

// build lays the four scenarios end to end and returns them keyed by name.
function build({ duration, rate, vus, gap = 5 }) {
    const order = ['baseline', 'proxied', 'attack', 'mixed'];
    const scenarios = {};

    let start = 0;
    for (const name of order) {
        scenarios[name] = stage(name, start, duration, rate, vus);
        start += duration + gap;
    }
    return scenarios;
}

export const PROFILES = {
    // What runs on every pull request. Short enough to keep a PR under a
    // minute of load, long enough that a p95 means something.
    smoke: {
        description: 'four 10-second stages, ~1 minute in total',
        scenarios: build({ duration: 10 * SECOND, rate: 50, vus: 20 }),
    },

    // The nightly run. Long enough for the audit queue to reach a steady state
    // and for a leak to start showing.
    full: {
        description: 'four 2-minute stages at a higher rate, ~9 minutes',
        scenarios: build({ duration: 120 * SECOND, rate: 200, vus: 60, gap: 10 }),
    },

    // Endurance. One scenario, held for half an hour, watching for the queue
    // depth and memory to drift rather than for a headline latency number.
    soak: {
        description: 'a single 30-minute stage at a moderate rate',
        scenarios: {
            proxied: {
                executor: 'constant-arrival-rate',
                exec: 'proxied',
                duration: '30m',
                rate: 100,
                timeUnit: '1s',
                preAllocatedVUs: 40,
                maxVUs: 160,
                tags: { scenario: 'proxied' },
                gracefulStop: '10s',
            },
        },
    },
};

export function selectProfile(name) {
    const profile = PROFILES[name];
    if (!profile) {
        throw new Error(
            `unknown load profile "${name}"; choose one of: ${Object.keys(PROFILES).join(', ')}`,
        );
    }
    return profile;
}
