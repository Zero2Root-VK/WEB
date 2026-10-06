import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { motion } from "framer-motion";
import {
  ArrowRight,
  Boxes,
  Braces,
  Fingerprint,
  GitBranch,
  Lock,
  Radar,
  Repeat,
  ScanSearch,
  ShieldAlert,
  Sigma,
  Terminal,
  Users,
} from "lucide-react";
import { Link } from "react-router";

const CONSOLE_HREF = "/auth?returnTo=/dashboard";

const fadeUp = {
  initial: { opacity: 0, y: 16 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-80px" },
  transition: { duration: 0.5 },
};

const CAPABILITIES = [
  {
    icon: ShieldAlert,
    title: "BOLA / IDOR",
    body: "Directional object probes (A→B, B→A), including no-ID-substitution replays of an observed reference.",
  },
  {
    icon: Fingerprint,
    title: "Horizontal & vertical escalation",
    body: "Role-rank comparison across every privileged function, with positive controls to prove the engine is not guessing.",
  },
  {
    icon: GitBranch,
    title: "Workflow & state transitions",
    body: "Lifecycle modelled as a state machine. Out-of-sequence transitions are executed and disproved by the resulting state.",
  },
  {
    icon: Boxes,
    title: "Tenant isolation",
    body: "Cross-tenant reads and writes resolved against the owning tenant before a single byte is returned.",
  },
  {
    icon: Braces,
    title: "Mass assignment",
    body: "Protected properties such as owner, role and tenant are injected and then diffed against the persisted record.",
  },
  {
    icon: Repeat,
    title: "Replay & business logic",
    body: "Single-use tokens, coupon reuse, double refunds and sequence bypasses confirmed by state change, not status code.",
  },
];

const PIPELINE = [
  { step: "01", label: "Model", detail: "Identities, objects, roles, tenants" },
  { step: "02", label: "Map", detail: "Unified endpoint registry" },
  { step: "03", label: "Plan", detail: "Authorization test matrix" },
  { step: "04", label: "Execute", detail: "Scope-guarded probes" },
  { step: "05", label: "Diff", detail: "Reference vs actual vs delta" },
  { step: "06", label: "Confirm", detail: "Evidence-scored findings" },
];

const TERMINAL_LINES: Array<{ tone: string; text: string }> = [
  { tone: "muted", text: "$ wabve verify --engagement acme-staging --profile balanced" },
  { tone: "info", text: "[SCOPE]   allowlist staging.acme.test /api/ · 5 req/s · budget 2000" },
  { tone: "info", text: "[MODEL]   14 objects · 5 roles · 2 tenants · 18 endpoints" },
  { tone: "test", text: "[TEST]    User B → GET /api/invoices/1001" },
  { tone: "verify", text: "[VERIFY]  reference=DENY   target=ALLOW" },
  { tone: "verify", text: "[VERIFY]  state delta: status PAID → CANCELLED" },
  { tone: "confirm", text: "[CONFIRMED] WABVE-001  Cross-user invoice modification  confidence 90/100" },
];

const TONE_CLASS: Record<string, string> = {
  muted: "text-muted-foreground",
  info: "text-sky-300",
  test: "text-foreground/80",
  verify: "text-amber-300",
  confirm: "text-teal-300",
};

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative flex size-8 items-center justify-center rounded-md border border-primary/40 bg-primary/10">
        <Sigma className="size-4 text-primary" />
      </div>
      <div className="leading-none">
        <span className="font-mono text-sm font-semibold tracking-[0.2em] text-foreground">
          WABVE
        </span>
        <p className="mt-0.5 font-mono text-[9px] tracking-[0.14em] text-muted-foreground uppercase">
          authorization engine
        </p>
      </div>
    </div>
  );
}

export default function Landing() {
  return (
    <div className="relative min-h-screen overflow-x-hidden bg-background text-foreground">
      {/* backdrop */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.55] bg-[linear-gradient(to_right,oklch(1_0_0/4%)_1px,transparent_1px),linear-gradient(to_bottom,oklch(1_0_0/4%)_1px,transparent_1px)] bg-[size:56px_56px] [mask-image:radial-gradient(ellipse_at_top,black,transparent_75%)]"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute -top-40 left-1/2 size-[38rem] -translate-x-1/2 rounded-full bg-primary/15 blur-[140px]"
      />

      {/* nav */}
      <header className="sticky top-0 z-30 border-b border-border/60 bg-background/80 backdrop-blur-md">
        <div className="mx-auto flex h-14 w-full max-w-6xl items-center justify-between px-4 sm:px-6">
          <Logo />
          <nav className="hidden items-center gap-6 font-mono text-xs tracking-wide text-muted-foreground uppercase md:flex">
            <a className="transition-colors hover:text-foreground" href="#principle">
              Principle
            </a>
            <a className="transition-colors hover:text-foreground" href="#capabilities">
              Capabilities
            </a>
            <a className="transition-colors hover:text-foreground" href="#pipeline">
              Pipeline
            </a>
            <a className="transition-colors hover:text-foreground" href="#evidence">
              Evidence
            </a>
          </nav>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" asChild className="font-mono text-xs">
              <Link to={CONSOLE_HREF}>Sign in</Link>
            </Button>
            <Button size="sm" asChild className="gap-1.5 font-mono text-xs">
              <Link to={CONSOLE_HREF}>
                Open console
                <ArrowRight className="size-3.5" />
              </Link>
            </Button>
          </div>
        </div>
      </header>

      <main className="relative mx-auto w-full max-w-6xl px-4 sm:px-6">
        {/* hero */}
        <section className="grid gap-12 py-16 lg:grid-cols-[1.05fr_0.95fr] lg:items-center lg:py-24">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
            <Badge
              variant="outline"
              className="gap-2 rounded-full border-primary/30 bg-primary/5 px-3 py-1 font-mono text-[10px] tracking-[0.16em] text-primary uppercase"
            >
              <span className="size-1.5 animate-pulse rounded-full bg-primary" />
              Differential authorization verification
            </Badge>
            <h1 className="mt-5 text-4xl leading-[1.05] font-semibold tracking-tight sm:text-5xl">
              HTTP 200 is not a finding.
              <span className="block text-muted-foreground">
                A state delta is.
              </span>
            </h1>
            <p className="mt-5 max-w-xl text-sm leading-6 text-muted-foreground sm:text-base">
              WABVE models who can do what — then proves whether the application
              actually enforces it. Every probe is judged against a reference
              policy and a before/after snapshot, so a finding is backed by
              evidence instead of a status code.
            </p>
            <div className="mt-7 flex flex-wrap items-center gap-3">
              <Button asChild size="lg" className="gap-2 font-mono text-xs tracking-wide">
                <Link to={CONSOLE_HREF}>
                  Run an engagement
                  <ArrowRight className="size-4" />
                </Link>
              </Button>
              <Button
                asChild
                size="lg"
                variant="outline"
                className="gap-2 border-border/70 font-mono text-xs tracking-wide"
              >
                <a href="#principle">
                  <Terminal className="size-4" />
                  See the method
                </a>
              </Button>
            </div>
            <dl className="mt-9 grid max-w-lg grid-cols-3 gap-4 border-t border-border/60 pt-6">
              {[
                { k: "Probes per engagement", v: "30+" },
                { k: "Test classes", v: "8" },
                { k: "Verdicts", v: "4" },
              ].map((item) => (
                <div key={item.k}>
                  <dt className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    {item.k}
                  </dt>
                  <dd className="mt-1 text-xl font-semibold text-primary">{item.v}</dd>
                </div>
              ))}
            </dl>
          </motion.div>

          {/* terminal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.97 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.6, delay: 0.15 }}
          >
            <Card className="overflow-hidden border-border/70 bg-card/70 py-0 shadow-2xl shadow-black/40 backdrop-blur">
              <div className="flex items-center gap-2 border-b border-border/60 bg-muted/30 px-4 py-2.5">
                <span className="size-2.5 rounded-full bg-red-500/70" />
                <span className="size-2.5 rounded-full bg-amber-500/70" />
                <span className="size-2.5 rounded-full bg-teal-400/70" />
                <span className="ml-2 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                  live test console
                </span>
                <span className="ml-auto flex items-center gap-1.5 font-mono text-[10px] text-primary">
                  <span className="size-1.5 animate-pulse rounded-full bg-primary" />
                  streaming
                </span>
              </div>
              <CardContent className="space-y-1.5 px-4 py-4 font-mono text-[11px] leading-relaxed">
                {TERMINAL_LINES.map((line, i) => (
                  <motion.p
                    key={line.text}
                    initial={{ opacity: 0, x: -6 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.4 + i * 0.22, duration: 0.3 }}
                    className={cn("whitespace-pre-wrap", TONE_CLASS[line.tone])}
                  >
                    {line.text}
                  </motion.p>
                ))}
                <div className="grid grid-cols-2 gap-3 pt-3">
                  {[
                    ["Paid → Cancelled", "state delta"],
                    ["User B → User A", "identity delta"],
                  ].map(([value, label]) => (
                    <div
                      key={label}
                      className="rounded-md border border-border/60 bg-background/60 px-3 py-2"
                    >
                      <p className="text-[10px] tracking-widest text-muted-foreground uppercase">
                        {label}
                      </p>
                      <p className="mt-0.5 text-xs text-foreground/90">{value}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </section>

        {/* principle */}
        <section id="principle" className="border-t border-border/60 py-16">
          <motion.div {...fadeUp} className="max-w-3xl">
            <p className="font-mono text-[10px] tracking-[0.2em] text-primary uppercase">
              The core principle
            </p>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">
              Test behaviour, not responses.
            </h2>
            <p className="mt-3 text-sm leading-6 text-muted-foreground">
              A scanner that treats <span className="font-mono text-foreground/80">200 OK</span> as
              proof floods a report with noise. WABVE asks a longer question
              before it claims anything.
            </p>
          </motion.div>

          <div className="mt-10 grid gap-4 lg:grid-cols-2">
            <motion.div {...fadeUp}>
              <Card className="h-full border-border/60 bg-card/40 py-0 shadow-none">
                <CardContent className="px-5 py-5">
                  <p className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    traditional
                  </p>
                  <div className="mt-4 space-y-2 font-mono text-xs text-muted-foreground">
                    {["Request", "Response", "Status code", "Finding"].map((s) => (
                      <div
                        key={s}
                        className="rounded border border-border/50 bg-background/40 px-3 py-2"
                      >
                        {s}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div {...fadeUp} transition={{ duration: 0.5, delay: 0.1 }}>
              <Card className="h-full border-primary/30 bg-primary/[0.04] py-0 shadow-none">
                <CardContent className="px-5 py-5">
                  <p className="font-mono text-[10px] tracking-widest text-primary uppercase">
                    wabve
                  </p>
                  <div className="mt-4 grid grid-cols-2 gap-2 font-mono text-xs">
                    {[
                      "Identity",
                      "Role",
                      "Object",
                      "Action",
                      "Current state",
                      "Response",
                      "Post-state",
                      "State delta",
                      "Authz decision",
                      "Evidence",
                      "Finding",
                    ].map((s, i) => (
                      <div
                        key={s}
                        className={cn(
                          "rounded border px-3 py-2",
                          i >= 7
                            ? "border-primary/40 bg-primary/10 text-primary"
                            : "border-border/50 bg-background/40 text-foreground/75",
                        )}
                      >
                        {s}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </section>

        {/* capabilities */}
        <section id="capabilities" className="border-t border-border/60 py-16">
          <motion.div {...fadeUp} className="max-w-3xl">
            <p className="font-mono text-[10px] tracking-[0.2em] text-primary uppercase">
              Attack surface
            </p>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">
              Focused on what scanners get wrong.
            </h2>
            <p className="mt-3 text-sm leading-6 text-muted-foreground">
              Authorization and business-logic defects are contextual. WABVE
              keeps those modules deep instead of becoming another generic
              vulnerability scanner.
            </p>
          </motion.div>

          <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {CAPABILITIES.map((cap, i) => (
              <motion.div key={cap.title} {...fadeUp} transition={{ duration: 0.45, delay: i * 0.05 }}>
                <Card className="h-full border-border/60 bg-card/40 py-0 shadow-none transition-colors hover:border-primary/30 hover:bg-card/70">
                  <CardContent className="px-5 py-5">
                    <div className="flex size-9 items-center justify-center rounded-md border border-primary/30 bg-primary/10">
                      <cap.icon className="size-4 text-primary" />
                    </div>
                    <h3 className="mt-4 text-sm font-semibold">{cap.title}</h3>
                    <p className="mt-2 text-xs leading-5 text-muted-foreground">{cap.body}</p>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </section>

        {/* pipeline */}
        <section id="pipeline" className="border-t border-border/60 py-16">
          <motion.div {...fadeUp} className="max-w-3xl">
            <p className="font-mono text-[10px] tracking-[0.2em] text-primary uppercase">
              How it runs
            </p>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">
              From target to confirmed finding.
            </h2>
          </motion.div>

          <div className="mt-10 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {PIPELINE.map((stage, i) => (
              <motion.div
                key={stage.step}
                {...fadeUp}
                transition={{ duration: 0.45, delay: i * 0.05 }}
                className="group relative overflow-hidden rounded-lg border border-border/60 bg-card/40 px-5 py-4"
              >
                <span className="font-mono text-[10px] tracking-widest text-primary">
                  {stage.step}
                </span>
                <p className="mt-2 text-sm font-semibold">{stage.label}</p>
                <p className="mt-1 text-xs text-muted-foreground">{stage.detail}</p>
                <span className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
              </motion.div>
            ))}
          </div>

          <motion.div {...fadeUp} className="mt-8">
            <Card className="border-border/60 bg-card/40 py-0 shadow-none">
              <CardContent className="grid gap-6 px-6 py-6 sm:grid-cols-3">
                {[
                  {
                    icon: Radar,
                    title: "Scope guard",
                    body: "Host and path allowlist, rate limit, request budget, kill switch and audit log on every dispatch.",
                  },
                  {
                    icon: ScanSearch,
                    title: "Deterministic engine",
                    body: "The engine owns authentication, execution, state capture and evidence. No model declares a finding.",
                  },
                  {
                    icon: Users,
                    title: "Multi-identity proof",
                    body: "User A, User B, tenant-scoped users, managers, administrators and anonymous probes in one matrix.",
                  },
                ].map((item) => (
                  <div key={item.title} className="flex gap-3">
                    <div className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md border border-border/60 bg-background/50">
                      <item.icon className="size-4 text-primary" />
                    </div>
                    <div>
                      <p className="text-sm font-medium">{item.title}</p>
                      <p className="mt-1 text-xs leading-5 text-muted-foreground">{item.body}</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </motion.div>
        </section>

        {/* evidence */}
        <section id="evidence" className="border-t border-border/60 py-16">
          <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr]">
            <motion.div {...fadeUp}>
              <p className="font-mono text-[10px] tracking-[0.2em] text-primary uppercase">
                Evidence, not opinion
              </p>
              <h2 className="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">
                Every finding ships with its proof.
              </h2>
              <p className="mt-3 text-sm leading-6 text-muted-foreground">
                Findings carry a severity, a confidence score derived from
                weighted evidence signals, the CWE and OWASP mapping, the
                attacker and victim identity, the request, the response, and the
                before/after state that makes it reproducible.
              </p>
              <ul className="mt-6 space-y-3 text-sm">
                {[
                  "Reference policy vs. target behaviour, per probe",
                  "Before/after state snapshots with a field-level delta",
                  "Confidence bands: Confirmed · High · Medium · Inconclusive",
                  "Exports in HTML, PDF, JSON, Markdown, SARIF and CSV",
                ].map((item) => (
                  <li key={item} className="flex items-start gap-2.5 text-muted-foreground">
                    <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-primary" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
              <Button asChild className="mt-7 gap-2 font-mono text-xs">
                <Link to={CONSOLE_HREF}>
                  Start an engagement
                  <ArrowRight className="size-3.5" />
                </Link>
              </Button>
            </motion.div>

            <motion.div {...fadeUp} transition={{ duration: 0.5, delay: 0.1 }}>
              <Card className="overflow-hidden border-border/70 bg-card/60 py-0 shadow-xl shadow-black/30">
                <div className="flex flex-wrap items-center gap-2 border-b border-border/60 bg-muted/30 px-4 py-3">
                  <Badge variant="outline" className="border-red-500/40 font-mono text-[10px] text-red-300 uppercase">
                    WABVE-001
                  </Badge>
                  <span className="text-sm font-medium">Cross-user order modification</span>
                  <Badge variant="outline" className="ml-auto border-teal-400/40 font-mono text-[10px] text-teal-200 uppercase">
                    Confirmed · 90
                  </Badge>
                </div>
                <CardContent className="space-y-3 px-4 py-4 font-mono text-[11px]">
                  {[
                    ["Endpoint", "PUT /api/orders/501"],
                    ["Attacker", "User B (standard, tenant-a)"],
                    ["Victim", "User A (standard, tenant-a)"],
                  ].map(([k, v]) => (
                    <div key={k} className="flex gap-3">
                      <span className="w-20 shrink-0 text-muted-foreground uppercase">{k}</span>
                      <span className="text-foreground/85">{v}</span>
                    </div>
                  ))}
                  <div className="rounded-md border border-red-500/25 bg-red-500/[0.06] p-3">
                    <p className="text-muted-foreground">expected</p>
                    <p className="text-foreground/85">403 Forbidden</p>
                    <p className="mt-2 text-muted-foreground">actual</p>
                    <p className="text-foreground/85">200 OK — write persisted</p>
                  </div>
                  <div className="rounded-md border border-amber-500/25 bg-amber-500/[0.06] p-3">
                    <p className="text-muted-foreground">state delta</p>
                    <p className="text-foreground/85">status&nbsp; PAID → CANCELLED</p>
                    <p className="text-foreground/85">owner&nbsp;&nbsp; User A → User C</p>
                  </div>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {["CWE-639", "A01:2021", "BOLA", "reproducible"].map((s) => (
                      <Badge
                        key={s}
                        variant="outline"
                        className="border-border/60 font-mono text-[10px] text-muted-foreground"
                      >
                        {s}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </section>

        {/* cta */}
        <section className="border-t border-border/60 py-16">
          <motion.div {...fadeUp}>
            <Card className="relative overflow-hidden border-primary/25 bg-card/50 py-0 shadow-none">
              <div
                aria-hidden
                className="pointer-events-none absolute -right-24 -top-24 size-72 rounded-full bg-primary/15 blur-[100px]"
              />
              <CardContent className="relative grid gap-6 px-6 py-10 sm:px-10 lg:grid-cols-[1.4fr_0.6fr] lg:items-center">
                <div>
                  <div className="flex items-center gap-2 font-mono text-[10px] tracking-[0.2em] text-primary uppercase">
                    <Lock className="size-3.5" />
                    Built for testers, bug bounty and AppSec teams
                  </div>
                  <h2 className="mt-4 text-2xl font-semibold tracking-tight sm:text-3xl">
                    Model the app. Prove the gap.
                  </h2>
                  <p className="mt-3 max-w-xl text-sm leading-6 text-muted-foreground">
                    Create an engagement, declare identities and scope, and watch
                    the deterministic engine build the authorization matrix and
                    confirm what the application failed to enforce.
                  </p>
                </div>
                <div className="flex flex-col gap-3">
                  <Button asChild size="lg" className="gap-2 font-mono text-xs tracking-wide">
                    <Link to={CONSOLE_HREF}>
                      Open the console
                      <ArrowRight className="size-4" />
                    </Link>
                  </Button>
                  <p className="text-center font-mono text-[10px] text-muted-foreground">
                    scope-guarded · non-destructive by default
                  </p>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </section>
      </main>

      <footer className="relative border-t border-border/60">
        <div className="mx-auto flex w-full max-w-6xl flex-col gap-3 px-4 py-8 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <Logo />
          <p className="font-mono text-[10px] tracking-wide text-muted-foreground">
            Authorization &amp; business logic verification · detections are always
            evidence-backed
          </p>
        </div>
      </footer>
    </div>
  );
}
