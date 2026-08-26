// The §8.2 budget, written as something that can fail a build.
//
// k6 exits non-zero when a threshold is broken, which is what turns the
// non-functional requirements of the technical document from a paragraph into a
// gate. Each number below is traceable to a line in that document; none of them
// were chosen to make the suite pass.

// LATENCY_BUDGET_MS is §8.2's "added latency under 50 ms at normal load".
//
// It is applied to the *total* time through the proxy rather than to the
// difference from the baseline, because a threshold has to be a property of one
// metric. That makes it a strictly harder test: total = added + backend, so
// passing it means the added part is comfortably inside the budget. The
// measured difference is printed in the summary, and that is the number to
// compare with the manual's §5.1 table.
// Overridable so the gate itself can be tested: setting it to something
// unreachable must turn the run red. A threshold nobody has ever seen fail is
// not a threshold, it is a decoration.
export const LATENCY_BUDGET_MS = Number(__ENV.OS_LOAD_LATENCY_BUDGET_MS) || 50;

// §8.2 sets an availability target of 99%. Under load, over a short window,
// anything above a fraction of a percent of failed requests is a real problem
// rather than noise.
export const ERROR_BUDGET = 0.01;

export const thresholds = {
    // --- The protected site stays fast (§8.2) --------------------------------
    'http_req_duration{scenario:proxied}': [
        { threshold: `p(95)<${LATENCY_BUDGET_MS}`, abortOnFail: false },
    ],
    'http_req_duration{scenario:mixed}': [`p(95)<${LATENCY_BUDGET_MS}`],

    // --- The protected site stays up (§8.2) ----------------------------------
    'http_req_failed{scenario:proxied}': [`rate<${ERROR_BUDGET}`],
    'http_req_failed{scenario:baseline}': [`rate<${ERROR_BUDGET}`],

    // --- The filtering still works under load (RF-03) ------------------------
    //
    // The one that matters most and is easiest to forget. A proxy that gets
    // fast by dropping the rule chain under pressure would pass every latency
    // threshold above. http_req_failed is not used here: an attack is *meant*
    // to come back 403, which k6 would otherwise count as a failure.
    'checks{scenario:attack}': ['rate>0.99'],
    'checks{scenario:proxied}': ['rate>0.99'],
    'checks{scenario:mixed}': ['rate>0.99'],

    // --- The baseline is a baseline ------------------------------------------
    //
    // If the demo backend is itself slow, the comparison says nothing. This
    // catches a run made on a machine too loaded to measure anything.
    'http_req_duration{scenario:baseline}': [
        { threshold: `p(95)<${LATENCY_BUDGET_MS}`, abortOnFail: true },
    ],
};
