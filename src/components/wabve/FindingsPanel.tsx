import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { Doc } from "@/convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import { ArrowRight, ShieldAlert } from "lucide-react";
import { useState } from "react";
import {
  CodeBlock,
  CONFIDENCE_CLASS,
  EmptyState,
  formatValue,
  PanelHeader,
  SEVERITY_CLASS,
  SEVERITY_ORDER,
  Tag,
} from "./shared";

interface DeltaEntry {
  field: string;
  before: unknown;
  after: unknown;
}

const FILTERS = ["all", "critical", "high", "medium", "low"] as const;

export function FindingsPanel({ findings }: { findings: Doc<"findings">[] }) {
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const sorted = findings
    .slice()
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  const visible = filter === "all" ? sorted : sorted.filter((f) => f.severity === filter);
  const selected = visible.find((f) => f._id === selectedId) ?? visible[0] ?? null;

  if (findings.length === 0) {
    return (
      <div className="space-y-6">
        <PanelHeader
          title="Findings"
          description="Confirmed authorization and business-logic defects, each backed by a differential verdict."
        />
        <EmptyState
          title="No findings"
          description="Nothing has been confirmed for this engagement. Run the engine or widen the testing profile."
        />
      </div>
    );
  }

  const delta = (selected?.stateDelta as DeltaEntry[] | undefined) ?? [];

  return (
    <div className="space-y-6">
      <PanelHeader
        title="Findings"
        description="Each finding carries the attacker and victim identity, the expected and actual decision, and the state delta that makes it reproducible."
        actions={
          <div className="flex flex-wrap gap-1.5">
            {FILTERS.map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => setFilter(value)}
                className={cn(
                  "rounded-full border px-2.5 py-1 font-mono text-[10px] tracking-wide uppercase transition-colors",
                  filter === value
                    ? "border-primary/50 bg-primary/10 text-primary"
                    : "border-border/60 text-muted-foreground hover:text-foreground",
                )}
              >
                {value}
              </button>
            ))}
          </div>
        }
      />

      <div className="grid gap-4 lg:grid-cols-[0.85fr_1.15fr]">
        <ScrollArea className="max-h-[42rem]">
          <div className="space-y-2 pr-2">
            {visible.map((finding) => (
              <button
                key={finding._id}
                type="button"
                onClick={() => setSelectedId(finding._id)}
                className={cn(
                  "w-full rounded-md border px-3.5 py-3 text-left transition-colors",
                  selected?._id === finding._id
                    ? "border-primary/40 bg-primary/[0.07]"
                    : "border-border/60 bg-card/40 hover:border-border",
                )}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] text-muted-foreground">{finding.code}</span>
                  <Tag className={SEVERITY_CLASS[finding.severity]}>{finding.severity}</Tag>
                  <Tag className={cn("ml-auto", CONFIDENCE_CLASS[finding.confidence])}>
                    {finding.confidence} · {finding.score}
                  </Tag>
                </div>
                <p className="mt-2 text-sm font-medium">{finding.title}</p>
                <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                  {finding.endpoint}
                </p>
              </button>
            ))}
          </div>
        </ScrollArea>

        {selected ? (
          <Card className="border-border/60 bg-card/40 py-0 shadow-none">
            <CardContent className="space-y-5 px-5 py-5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[11px] text-muted-foreground">{selected.code}</span>
                <Tag className={SEVERITY_CLASS[selected.severity]}>{selected.severity}</Tag>
                <Tag className={CONFIDENCE_CLASS[selected.confidence]}>
                  {selected.confidence} · {selected.score}/100
                </Tag>
                <Tag className="border-border/60 text-muted-foreground">
                  {selected.classification}
                </Tag>
                <Tag className="border-border/60 text-muted-foreground">{selected.cwe}</Tag>
                <Tag className="border-border/60 text-muted-foreground">{selected.owasp}</Tag>
              </div>

              <div>
                <h3 className="text-base font-semibold tracking-tight">{selected.title}</h3>
                <p className="mt-1 font-mono text-xs text-muted-foreground">{selected.endpoint}</p>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                {[
                  ["Attacker", selected.attacker],
                  ["Victim", selected.victim ?? "—"],
                  ["Expected", selected.expected],
                  ["Actual", selected.actual],
                  ["Parameter", selected.parameter ?? "—"],
                  ["Probe", selected.probe],
                ].map(([label, value]) => (
                  <div key={label} className="rounded-md border border-border/60 bg-background/40 px-3 py-2">
                    <p className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                      {label}
                    </p>
                    <p className="mt-0.5 font-mono text-[11px] text-foreground/85">{value}</p>
                  </div>
                ))}
              </div>

              <div className="grid gap-3 lg:grid-cols-2">
                <div>
                  <p className="mb-1.5 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    request
                  </p>
                  <CodeBlock>{selected.request}</CodeBlock>
                </div>
                <div>
                  <p className="mb-1.5 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    response
                  </p>
                  <CodeBlock>{selected.response}</CodeBlock>
                </div>
              </div>

              {delta.length > 0 ? (
                <div>
                  <p className="mb-2 flex items-center gap-2 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    <ShieldAlert className="size-3.5 text-red-400" />
                    state delta — the evidence
                  </p>
                  <div className="overflow-hidden rounded-md border border-red-500/25">
                    {delta.map((entry) => (
                      <div
                        key={entry.field}
                        className="flex items-center gap-3 border-b border-red-500/15 bg-red-500/[0.05] px-3 py-2 font-mono text-[11px] last:border-b-0"
                      >
                        <span className="w-28 shrink-0 text-muted-foreground">{entry.field}</span>
                        <span className="text-foreground/60 line-through">
                          {formatValue(entry.before)}
                        </span>
                        <ArrowRight className="size-3 text-red-400" />
                        <span className="text-red-300">{formatValue(entry.after)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="rounded-md border border-amber-500/25 bg-amber-500/[0.05] px-3 py-2.5 font-mono text-[11px] text-amber-200">
                  {selected.signals.includes("workflow_transition_violated")
                    ? "No field changed because the record had already reached the destination state — the violation is that the illegal transition was accepted at all."
                    : selected.signals.includes("privilege_boundary_crossed")
                      ? "The protected response body is the evidence: a lower-privileged identity received data from an administrator-only function."
                      : "No state change was observed — this finding rests on the protected record being returned to a non-owning identity."}
                </div>
              )}

              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="mb-1.5 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    state before
                  </p>
                  <CodeBlock className="max-h-40">
                    {formatState(selected.beforeState)}
                  </CodeBlock>
                </div>
                <div>
                  <p className="mb-1.5 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    state after
                  </p>
                  <CodeBlock className="max-h-40">
                    {formatState(selected.afterState)}
                  </CodeBlock>
                </div>
              </div>

              <div>
                <p className="mb-2 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                  evidence signals
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {selected.signals.map((signal) => (
                    <Tag key={signal} className="border-teal-400/25 text-teal-200/90">
                      {signal}
                    </Tag>
                  ))}
                </div>
              </div>

              <div>
                <p className="mb-2 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                  reproduction
                </p>
                <ol className="space-y-1.5">
                  {selected.reproduction.map((step, i) => (
                    <li key={step} className="flex gap-2.5 text-xs text-muted-foreground">
                      <span className="font-mono text-[10px] text-primary">{i + 1}.</span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ol>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-md border border-border/60 bg-background/40 px-3 py-3">
                  <p className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    impact
                  </p>
                  <p className="mt-1 text-xs leading-5 text-foreground/85">{selected.impact}</p>
                </div>
                <div className="rounded-md border border-teal-400/25 bg-teal-400/[0.04] px-3 py-3">
                  <p className="font-mono text-[10px] tracking-widest text-teal-300 uppercase">
                    remediation
                  </p>
                  <p className="mt-1 text-xs leading-5 text-foreground/85">{selected.remediation}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  );
}

function formatState(state: unknown): string {
  if (!state || typeof state !== "object") return "—";
  return Object.entries(state as Record<string, unknown>)
    .map(([key, value]) => `${key.padEnd(16)} ${formatValue(value)}`)
    .join("\n");
}
