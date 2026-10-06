import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { motion } from "framer-motion";
import { ArrowRight, Sigma } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router";

const CONSOLE_HREF = "/auth?returnTo=/dashboard";

/*
 * Every value on this page is something the engine actually emits.
 *
 * The classification rows below are the real mapping in real/reporting.ts:
 * the corroborating signal name is the exact token the differential oracle
 * pushes, and the CWE / OWASP pair is what `cweFor` and `owaspForCategory`
 * return for it. There is no invented feature copy here — if a row can't be
 * traced to the engine, it doesn't belong on the page.
 */
const CLASSES: Array<{
  klass: string;
  policy: string;
  signal: string;
  cwe: string;
  owasp: string;
}> = [
  {
    klass: "BOLA / IDOR",
    policy: "A read of a record the caller does not own is denied.",
    signal: "protected_record_returned",
    cwe: "CWE-639",
    owasp: "A01:2021",
  },
  {
    klass: "Unauthorized write",
    policy: "A non-owner's write is rejected before it commits.",
    signal: "server_state_changed",
    cwe: "CWE-862",
    owasp: "A01:2021",
  },
  {
    klass: "Mass assignment",
    policy: "owner, role and tenant are not client-settable.",
    signal: "protected_property_accepted",
    cwe: "CWE-915",
    owasp: "A08:2021",
  },
  {
    klass: "Function-level (BFLA)",
    policy: "A privileged function is reserved for a higher role.",
    signal: "privilege_boundary_crossed",
    cwe: "CWE-285",
    owasp: "A01:2021",
  },
  {
    klass: "Tenant isolation",
    policy: "A record is confined to its owning tenant.",
    signal: "tenant_boundary_crossed",
    cwe: "CWE-639",
    owasp: "A01:2021",
  },
  {
    klass: "Workflow bypass",
    policy: "Only the next legal transition is permitted.",
    signal: "workflow_transition_violated",
    cwe: "A04:2021",
    owasp: "insecure design",
  },
  {
    klass: "Replay / business logic",
    policy: "A single-use action is accepted exactly once.",
    signal: "replay_accepted",
    cwe: "A04:2021",
    owasp: "insecure design",
  },
];

/** The engine's real signal weights and confidence bands. */
const BANDS: Array<{ label: string; rule: string; tone: string }> = [
  { label: "Confirmed", rule: "score ≥ 90", tone: "text-teal-300" },
  { label: "High", rule: "score ≥ 70", tone: "text-teal-300/80" },
  { label: "Medium", rule: "score ≥ 40", tone: "text-amber-300/90" },
  { label: "Inconclusive", rule: "score < 40", tone: "text-muted-foreground" },
];

/** The eight stages the pipeline actually schedules. */
const STAGES: Array<{ n: string; label: string; detail: string }> = [
  { n: "01", label: "Scope", detail: "Host and path allowlist, rate limit, budget, kill switch" },
  { n: "02", label: "Discovery", detail: "Endpoint registry from OpenAPI, HTML, JS, HAR or import" },
  { n: "03", label: "Identity", detail: "Session verification for every declared credential" },
  { n: "04", label: "Model", detail: "Objects, roles, tenants and resource types" },
  { n: "05", label: "Matrix", detail: "One actor × one object × one endpoint per probe" },
  { n: "06", label: "Execution", detail: "Scope-guarded probes with full request capture" },
  { n: "07", label: "Findings", detail: "Reference vs. actual vs. state delta → verdict" },
  { n: "08", label: "Report", detail: "HTML, PDF, JSON, Markdown, SARIF and CSV exports" },
];

/** Real field names from the stored test row, shown verbatim. */
const EVIDENCE_JSON = [
  '{',
  '  "probe": "cross_identity_write",',
  '  "actorKey": "user_b",',
  '  "victimKey": "user_a",',
  '  "objectRef": "501",',
  '  "expectation": "DENY",',
  '  "actual": "ALLOW",',
  '  "statusCode": 200,',
  '  "signals": [',
  '    "unauthorized_access_confirmed",',
  '    "server_state_changed",',
  '    "differential_confirmed",',
  '    "reproducible"',
  '  ],',
  '  "stateDelta": [',
  '    { "field": "status",',
  '      "before": "PAID",',
  '      "after": "CANCELLED" }',
  '  ],',
  '  "confidence": 100',
  '}',
];

const fadeUp = {
  initial: { opacity: 0, y: 14 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-60px" },
  transition: { duration: 0.45, ease: "easeOut" as const },
};

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <Sigma className="size-4 text-primary" aria-hidden />
      <div className="leading-none">
        <span className="font-mono text-[13px] font-semibold tracking-[0.22em]">WABVE</span>
        <p className="mt-1 font-mono text-[9px] tracking-[0.16em] text-muted-foreground uppercase">
          authorization verification engine
        </p>
      </div>
    </div>
  );
}

/** A small monospace section label — no pill, no pulse, no icon. */
function Kicker({ children }: { children: ReactNode }) {
  return (
    <p className="font-mono text-[10px] tracking-[0.24em] text-muted-foreground uppercase">
      <span className="mr-2 text-primary">/</span>
      {children}
    </p>
  );
}

export default function Landing() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-30 border-b border-border/70 bg-background/85 backdrop-blur-md">
        <div className="mx-auto flex h-16 w-full max-w-6xl items-center gap-6 px-5 sm:px-8">
          <Link to="/" className="shrink-0">
            <Logo />
          </Link>
          <nav className="ml-auto hidden items-center gap-7 font-mono text-[11px] tracking-[0.12em] text-muted-foreground uppercase md:flex">
            <a className="transition-colors hover:text-foreground" href="#principle">
              Method
            </a>
            <a className="transition-colors hover:text-foreground" href="#classes">
              Test classes
            </a>
            <a className="transition-colors hover:text-foreground" href="#pipeline">
              Pipeline
            </a>
            <a className="transition-colors hover:text-foreground" href="#evidence">
              Evidence
            </a>
          </nav>
          <div className="ml-auto flex items-center gap-5 md:ml-0">
            <Link
              to={CONSOLE_HREF}
              className="hidden font-mono text-[11px] tracking-[0.12em] text-muted-foreground uppercase transition-colors hover:text-foreground sm:block"
            >
              Sign in
            </Link>
            <Button asChild size="sm" className="gap-1.5 font-mono text-[11px]">
              <Link to={CONSOLE_HREF}>
                Open console
                <ArrowRight className="size-3.5" />
              </Link>
            </Button>
          </div>
        </div>
      </header>

      <main>
        {/* ── hero ─────────────────────────────────────────────── */}
        <section className="mx-auto w-full max-w-6xl px-5 pt-16 pb-14 sm:px-8 sm:pt-24 sm:pb-20">
          <div className="grid gap-14 lg:grid-cols-[1.08fr_0.92fr] lg:items-start lg:gap-16">
            <div>
              <h1 className="text-4xl leading-[1.04] font-semibold tracking-[-0.02em] text-balance sm:text-5xl lg:text-6xl">
                HTTP&nbsp;200 is not a finding.
                <br />
                <span className="text-muted-foreground">A state delta is.</span>
              </h1>

              <p className="mt-7 max-w-xl text-[15px] leading-7 text-muted-foreground text-pretty">
                WABVE models who is allowed to do what, then checks whether the
                application actually enforces it. Each probe is judged against a
                reference policy and a before/after snapshot, so a finding carries
                the evidence that proves it — a status code never does.
              </p>

              <div className="mt-9 flex flex-wrap items-center gap-x-6 gap-y-3">
                <Button asChild size="lg" className="gap-2 font-mono text-xs tracking-wide">
                  <Link to={CONSOLE_HREF}>
                    Run an engagement
                    <ArrowRight className="size-4" />
                  </Link>
                </Button>
                <a
                  href="#principle"
                  className="font-mono text-[11px] tracking-[0.12em] text-muted-foreground uppercase underline decoration-border underline-offset-[6px] transition-colors hover:text-foreground"
                >
                  Read the method
                </a>
              </div>

              <dl className="mt-12 grid max-w-lg grid-cols-3 border-t border-border/70">
                {[
                  ["Pipeline stages", "8"],
                  ["Export formats", "6"],
                  ["Verdicts", "4"],
                ].map(([label, value]) => (
                  <div key={label} className="border-r border-border/70 pt-4 pr-4 last:border-r-0">
                    <dt className="font-mono text-[9px] tracking-[0.16em] text-muted-foreground uppercase">
                      {label}
                    </dt>
                    <dd className="mt-2 font-mono text-2xl leading-none font-semibold tabular-nums">
                      {value}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>

            {/* one artifact, presented as documentation rather than a fake terminal */}
            <motion.figure
              initial={{ opacity: 0, y: 18 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="lg:mt-2"
            >
              <figcaption className="flex items-baseline justify-between gap-4 border-b border-border/70 pb-3">
                <span className="font-mono text-[10px] tracking-[0.16em] text-muted-foreground uppercase">
                  Finding · report excerpt
                </span>
                <span className="font-mono text-[10px] text-muted-foreground">WABVE-001</span>
              </figcaption>

              <div className="mt-5 flex flex-wrap items-baseline gap-x-4 gap-y-1">
                <span className="font-mono text-[11px] font-semibold tracking-[0.12em] text-red-300 uppercase">
                  high
                </span>
                <h2 className="text-base font-semibold tracking-tight">
                  Cross-user order modification
                </h2>
                <span className="ml-auto font-mono text-[10px] text-teal-300">Confirmed · 100</span>
              </div>

              <dl className="mt-5 space-y-2 font-mono text-[11px]">
                {[
                  ["endpoint", "PUT /api/orders/501"],
                  ["classification", "BOLA / IDOR"],
                  ["mapping", "CWE-639 · A01:2021"],
                  ["actor", "user_b (standard, tenant-a)"],
                  ["victim", "user_a (standard, tenant-a)"],
                ].map(([k, v]) => (
                  <div key={k} className="flex gap-4">
                    <dt className="w-24 shrink-0 text-muted-foreground uppercase">{k}</dt>
                    <dd className="text-foreground/85">{v}</dd>
                  </div>
                ))}
              </dl>

              <div className="mt-6 border-l-2 border-border pl-4">
                <p className="font-mono text-[10px] tracking-[0.16em] text-muted-foreground uppercase">
                  reference vs. actual
                </p>
                <p className="mt-2 font-mono text-[11px] text-foreground/85">
                  403 Forbidden <span className="text-muted-foreground">expected</span>
                </p>
                <p className="font-mono text-[11px] text-red-300">
                  200 OK — write committed <span className="text-muted-foreground">actual</span>
                </p>
              </div>

              <div className="mt-5 border-l-2 border-primary/50 pl-4">
                <p className="font-mono text-[10px] tracking-[0.16em] text-muted-foreground uppercase">
                  state delta · owner re-read
                </p>
                <p className="mt-2 font-mono text-[11px] text-foreground/85">
                  status&nbsp;&nbsp;PAID → CANCELLED
                </p>
                <p className="font-mono text-[11px] text-foreground/85">
                  version&nbsp;7 → 8
                </p>
              </div>

              <p className="mt-6 font-mono text-[10px] leading-5 text-muted-foreground">
                Rendered by the engine's reporting layer from a stored test row.
              </p>
            </motion.figure>
          </div>
        </section>

        {/* ── method ───────────────────────────────────────────── */}
        <section id="principle" className="border-t border-border/70">
          <div className="mx-auto w-full max-w-6xl px-5 py-16 sm:px-8 sm:py-20">
            <motion.div {...fadeUp} className="grid gap-6 lg:grid-cols-[0.42fr_0.58fr]">
              <div>
                <Kicker>Method</Kicker>
                <h2 className="mt-4 text-3xl leading-tight font-semibold tracking-tight text-balance sm:text-4xl">
                  Judge behaviour, not responses.
                </h2>
              </div>
              <p className="text-[15px] leading-7 text-muted-foreground text-pretty lg:pt-8">
                A scanner that treats <span className="font-mono text-foreground/90">200 OK</span> as
                proof fills a report with noise. WABVE answers a longer question
                first: who is acting, on whose object, through which endpoint,
                from what state — and does the application let that happen?
              </p>
            </motion.div>

            {/* the evidence chain, drawn as a chain rather than a card grid */}
            <motion.div
              {...fadeUp}
              transition={{ duration: 0.45, delay: 0.08 }}
              className="mt-14 grid gap-px overflow-hidden border border-border/70 sm:grid-cols-2"
            >
              <div className="bg-card/30 p-6">
                <p className="font-mono text-[10px] tracking-[0.16em] text-muted-foreground uppercase">
                  Status-code scanners
                </p>
                <ol className="mt-5 space-y-2 font-mono text-[11px] text-muted-foreground">
                  {["request", "response", "200 OK", "finding"].map((step, i) => (
                    <li
                      key={step}
                      className={cn(
                        "border-l pl-3",
                        i === 3 ? "border-red-400/50 text-red-300" : "border-border/60",
                      )}
                    >
                      {step}
                    </li>
                  ))}
                </ol>
                <p className="mt-5 text-xs leading-6 text-muted-foreground">
                  A denied request that still returns 200, a cached page, or a
                  write that never committed all become findings.
                </p>
              </div>

              <div className="bg-primary/[0.045] p-6">
                <p className="font-mono text-[10px] tracking-[0.16em] text-primary uppercase">
                  WABVE
                </p>
                <ol className="mt-5 space-y-2 font-mono text-[11px]">
                  {[
                    "identity → role → tenant",
                    "reference policy",
                    "actual policy",
                    "before / after state",
                    "field-level delta",
                    "verdict + confidence",
                  ].map((step, i) => (
                    <li
                      key={step}
                      className={cn(
                        "border-l pl-3",
                        i >= 5 ? "border-primary/50 text-primary" : "border-border/60 text-foreground/80",
                      )}
                    >
                      {step}
                    </li>
                  ))}
                </ol>
                <p className="mt-5 text-xs leading-6 text-muted-foreground">
                  A finding is recorded only when the reference policy and the
                  target disagree <em className="text-foreground/80 not-italic">and</em> a
                  corroborating payload or a persisted state change proves it.
                </p>
              </div>
            </motion.div>

            {/* confidence ladder — the real weights and bands */}
            <motion.div {...fadeUp} className="mt-10">
              <p className="font-mono text-[10px] tracking-[0.16em] text-muted-foreground uppercase">
                Confidence · weighted evidence signals, capped at 100
              </p>
              <dl className="mt-4 grid border-t border-border/70 sm:grid-cols-4">
                {BANDS.map((band) => (
                  <div key={band.label} className="border-b border-border/70 py-4 pr-4 sm:border-b-0">
                    <dt className={cn("font-mono text-xs", band.tone)}>{band.label}</dt>
                    <dd className="mt-1.5 font-mono text-[10px] text-muted-foreground tabular-nums">
                      {band.rule}
                    </dd>
                  </div>
                ))}
              </dl>
            </motion.div>
          </div>
        </section>

        {/* ── test classes (specification table, not an icon grid) ── */}
        <section id="classes" className="border-t border-border/70">
          <div className="mx-auto w-full max-w-6xl px-5 py-16 sm:px-8 sm:py-20">
            <motion.div {...fadeUp} className="grid gap-6 lg:grid-cols-[0.42fr_0.58fr]">
              <div>
                <Kicker>Test classes</Kicker>
                <h2 className="mt-4 text-3xl leading-tight font-semibold tracking-tight text-balance sm:text-4xl">
                  Deep where scanners are shallow.
                </h2>
              </div>
              <p className="text-[15px] leading-7 text-muted-foreground text-pretty lg:pt-8">
                Authorization and business-logic defects are contextual. Each
                class below declares the policy it checks and the signal that has
                to appear in the evidence before a finding can be raised — the
                same mapping the report writes into every row.
              </p>
            </motion.div>

            <motion.div {...fadeUp} className="mt-12 border-t border-border/70">
              {CLASSES.map((row) => (
                <div
                  key={row.klass}
                  className="grid gap-x-6 gap-y-2 border-b border-border/70 py-4 sm:grid-cols-[minmax(0,1.15fr)_minmax(0,1.35fr)_auto] sm:items-baseline sm:py-3.5"
                >
                  <h3 className="text-sm font-semibold tracking-tight">{row.klass}</h3>
                  <p className="text-xs leading-5 text-muted-foreground">{row.policy}</p>
                  <div className="flex items-baseline gap-4 font-mono text-[10px] sm:justify-end">
                    <span className="text-teal-300/90">{row.signal}</span>
                    <span className="w-24 text-right text-muted-foreground">
                      {row.cwe} · {row.owasp}
                    </span>
                  </div>
                </div>
              ))}
            </motion.div>

            <p className="mt-4 font-mono text-[10px] leading-5 text-muted-foreground">
              Signal names are the exact tokens the differential oracle emits;
              CWE and OWASP are what the reporting layer writes for each.
            </p>
          </div>
        </section>

        {/* ── pipeline ─────────────────────────────────────────── */}
        <section id="pipeline" className="border-t border-border/70">
          <div className="mx-auto w-full max-w-6xl px-5 py-16 sm:px-8 sm:py-20">
            <motion.div {...fadeUp} className="grid gap-6 lg:grid-cols-[0.42fr_0.58fr]">
              <div>
                <Kicker>Pipeline</Kicker>
                <h2 className="mt-4 text-3xl leading-tight font-semibold tracking-tight text-balance sm:text-4xl">
                  Eight stages, each one auditable.
                </h2>
              </div>
              <p className="text-[15px] leading-7 text-muted-foreground text-pretty lg:pt-8">
                The engine owns authentication, execution, state capture and
                evidence. No model declares a finding, and no stage can skip the
                scope guard — the same guard that refuses a redirect hop is the
                one that refuses the first request.
              </p>
            </motion.div>

            <motion.ol {...fadeUp} className="mt-12 grid border-t border-border/70 sm:grid-cols-2 lg:grid-cols-4">
              {STAGES.map((stage) => (
                <li
                  key={stage.n}
                  className="border-b border-border/70 py-5 pr-6 sm:odd:border-r sm:odd:pr-6 lg:border-r lg:last:border-r-0"
                >
                  <span className="font-mono text-[10px] tracking-[0.16em] text-primary tabular-nums">
                    {stage.n}
                  </span>
                  <p className="mt-3 text-sm font-semibold tracking-tight">{stage.label}</p>
                  <p className="mt-1.5 text-xs leading-5 text-muted-foreground">{stage.detail}</p>
                </li>
              ))}
            </motion.ol>

            <motion.dl {...fadeUp} className="mt-12 grid gap-px overflow-hidden border border-border/70 sm:grid-cols-3">
              {[
                {
                  k: "Scope guard",
                  v: "Host and path allowlist, rate limit, request budget, kill switch and an audit log on every dispatch — including redirect hops.",
                },
                {
                  k: "Deterministic",
                  v: "The same engagement produces the same evidence, in the same order, on every run. Reports are reproducible.",
                },
                {
                  k: "Multi-identity",
                  v: "Standard users, tenant-scoped users, managers, administrators and anonymous probes in a single matrix.",
                },
              ].map((item) => (
                <div key={item.k} className="bg-card/30 p-6">
                  <dt className="font-mono text-[10px] tracking-[0.16em] text-foreground uppercase">
                    {item.k}
                  </dt>
                  <dd className="mt-3 text-xs leading-6 text-muted-foreground">{item.v}</dd>
                </div>
              ))}
            </motion.dl>
          </div>
        </section>

        {/* ── evidence ─────────────────────────────────────────── */}
        <section id="evidence" className="border-t border-border/70">
          <div className="mx-auto grid w-full max-w-6xl gap-12 px-5 py-16 sm:px-8 sm:py-20 lg:grid-cols-[0.9fr_1.1fr] lg:gap-16">
            <motion.div {...fadeUp}>
              <Kicker>Evidence</Kicker>
              <h2 className="mt-4 text-3xl leading-tight font-semibold tracking-tight text-balance sm:text-4xl">
                Every finding ships with its proof.
              </h2>
              <p className="mt-5 text-[15px] leading-7 text-muted-foreground text-pretty">
                Findings carry a severity, a confidence score derived from
                weighted evidence signals, the CWE and OWASP mapping, the actor
                and victim identity, the full request and response, and the
                before/after state that makes them reproducible.
              </p>

              <ul className="mt-8 border-t border-border/70">
                {[
                  ["Reference policy vs. target behaviour", "per probe"],
                  ["Before/after snapshots", "field-level delta"],
                  ["Confidence bands", "Confirmed · High · Medium · Inconclusive"],
                  ["Exports", "HTML · PDF · JSON · Markdown · SARIF · CSV"],
                ].map(([label, note]) => (
                  <li
                    key={label}
                    className="flex flex-wrap items-baseline gap-x-3 border-b border-border/70 py-3 last:border-b-0"
                  >
                    <span className="text-sm text-foreground/85">{label}</span>
                    <span className="font-mono text-[10px] text-muted-foreground">{note}</span>
                  </li>
                ))}
              </ul>

              <Button asChild className="mt-8 gap-2 font-mono text-xs">
                <Link to={CONSOLE_HREF}>
                  Start an engagement
                  <ArrowRight className="size-3.5" />
                </Link>
              </Button>
            </motion.div>

            <motion.figure
              {...fadeUp}
              transition={{ duration: 0.45, delay: 0.08 }}
              className="border border-border/70 bg-card/40"
            >
              <figcaption className="flex items-center justify-between gap-4 border-b border-border/70 px-5 py-3">
                <span className="font-mono text-[10px] tracking-[0.16em] text-muted-foreground uppercase">
                  Stored test row
                </span>
                <span className="font-mono text-[10px] text-teal-300">outcome: fail</span>
              </figcaption>
              <pre className="overflow-x-auto px-5 py-4 font-mono text-[11px] leading-6 text-foreground/80">
                <code>{EVIDENCE_JSON.join("\n")}</code>
              </pre>
              <p className="border-t border-border/70 px-5 py-3 font-mono text-[10px] leading-5 text-muted-foreground">
                Trimmed for width. The stored row also holds the request, the
                response bodies and the owner's post-attack re-read.
              </p>
            </motion.figure>
          </div>
        </section>

        {/* ── close ────────────────────────────────────────────── */}
        <section className="border-t border-border/70">
          <motion.div
            {...fadeUp}
            className="mx-auto grid w-full max-w-6xl gap-8 px-5 py-16 sm:px-8 sm:py-20 lg:grid-cols-[1.3fr_0.7fr] lg:items-end"
          >
            <div>
              <Kicker>Get started</Kicker>
              <h2 className="mt-4 text-3xl leading-tight font-semibold tracking-tight text-balance sm:text-4xl">
                Model the application. Prove the gap.
              </h2>
              <p className="mt-5 max-w-xl text-[15px] leading-7 text-muted-foreground text-pretty">
                Declare identities and scope, then let the engine build the
                authorization matrix and confirm what the application failed to
                enforce. Non-destructive and scope-guarded by default.
              </p>
            </div>
            <div className="lg:justify-self-end">
              <Button asChild size="lg" className="gap-2 font-mono text-xs tracking-wide">
                <Link to={CONSOLE_HREF}>
                  Open the console
                  <ArrowRight className="size-4" />
                </Link>
              </Button>
            </div>
          </motion.div>
        </section>
      </main>

      <footer className="border-t border-border/70">
        <div className="mx-auto flex w-full max-w-6xl flex-col gap-4 px-5 py-8 sm:flex-row sm:items-center sm:justify-between sm:px-8">
          <Logo />
          <p className="font-mono text-[10px] leading-5 text-muted-foreground">
            Authorization &amp; business-logic verification · findings are
            evidence-backed by construction
          </p>
        </div>
      </footer>
    </div>
  );
}
