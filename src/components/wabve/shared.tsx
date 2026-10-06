import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export const SEVERITY_CLASS: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/15 text-red-300",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-300",
  medium: "border-amber-500/40 bg-amber-500/15 text-amber-300",
  low: "border-sky-500/40 bg-sky-500/15 text-sky-300",
};

export const CONFIDENCE_CLASS: Record<string, string> = {
  Confirmed: "border-teal-400/40 bg-teal-400/15 text-teal-200",
  High: "border-teal-400/25 bg-teal-400/10 text-teal-300/90",
  Medium: "border-slate-400/25 bg-slate-400/10 text-slate-300",
  Inconclusive: "border-slate-500/25 bg-slate-500/10 text-slate-400",
};

export const OUTCOME_CLASS: Record<string, string> = {
  fail: "border-red-500/40 bg-red-500/10 text-red-300",
  pass: "border-teal-400/30 bg-teal-400/10 text-teal-300",
  inconclusive: "border-slate-400/25 bg-slate-400/10 text-slate-400",
  blocked: "border-amber-500/40 bg-amber-500/10 text-amber-300",
};

export const RISK_CLASS: Record<string, string> = {
  critical: "border-red-500/40 text-red-300",
  high: "border-orange-500/40 text-orange-300",
  medium: "border-amber-500/40 text-amber-300",
  low: "border-sky-500/40 text-sky-300",
};

export function Tag({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <Badge
      variant="outline"
      className={cn("font-mono text-[10px] tracking-wide uppercase", className)}
    >
      {children}
    </Badge>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <Tag className={SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.low}>{severity}</Tag>;
}

export function ProtocolBadge({ method }: { method: string }) {
  const tone =
    method === "GET"
      ? "border-sky-500/40 text-sky-300"
      : method === "POST"
        ? "border-teal-400/40 text-teal-300"
        : method === "DELETE"
          ? "border-red-500/40 text-red-300"
          : "border-amber-500/40 text-amber-300";
  return <Tag className={tone}>{method}</Tag>;
}

export function StatCard({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "default" | "primary" | "danger";
}) {
  return (
    <Card className="border-border/60 bg-card/60 py-0 shadow-none">
      <CardContent className="px-4 py-3">
        <p className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
          {label}
        </p>
        <p
          className={cn(
            "mt-1 text-2xl font-semibold tabular-nums",
            tone === "primary" && "text-primary",
            tone === "danger" && "text-red-400",
          )}
        >
          {value}
        </p>
        {hint ? <p className="mt-0.5 text-xs text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
  );
}

export function Meter({
  label,
  value,
  max,
  tone = "primary",
  suffix,
}: {
  label: string;
  value: number;
  max: number;
  tone?: "primary" | "danger" | "warning";
  suffix?: string;
}) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between gap-3">
        <span className="font-mono text-[11px] tracking-wide text-muted-foreground uppercase">
          {label}
        </span>
        <span className="font-mono text-xs tabular-nums text-foreground/80">
          {suffix ?? `${value}/${max} · ${pct}%`}
        </span>
      </div>
      <Progress
        value={pct}
        className={cn(
          "h-1.5 bg-muted/60",
          tone === "danger" && "[&>[data-slot=progress-indicator]]:bg-red-500",
          tone === "warning" && "[&>[data-slot=progress-indicator]]:bg-amber-500",
        )}
      />
    </div>
  );
}

export function CodeBlock({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <pre
      className={cn(
        "overflow-x-auto rounded-md border border-border/60 bg-background/70 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap text-foreground/85",
        className,
      )}
    >
      {children}
    </pre>
  );
}

export function PanelHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
        {description ? (
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <Card className="border-dashed border-border/70 bg-transparent py-0 shadow-none">
      <CardContent className="flex flex-col items-center gap-2 px-6 py-10 text-center">
        <p className="text-sm font-medium">{title}</p>
        <p className="max-w-md text-xs text-muted-foreground">{description}</p>
        {children ? <div className="mt-3">{children}</div> : null}
      </CardContent>
    </Card>
  );
}

export const STAGES = [
  { key: "scope", label: "Scope guard" },
  { key: "discovery", label: "Discovery" },
  { key: "identity", label: "Identity manager" },
  { key: "model", label: "Application model" },
  { key: "matrix", label: "Test matrix" },
  { key: "execution", label: "Attacks" },
  { key: "findings", label: "Verification" },
  { key: "report", label: "Reporting" },
];

export const CATEGORY_LABEL: Record<string, string> = {
  authorization: "Authorization",
  tenant: "Tenant isolation",
  bfla: "Function-level authz",
  method: "HTTP method",
  property: "Property-level",
  workflow: "Workflow",
  business: "Business logic",
  session: "Session",
};

export const PROFILES = [
  {
    value: "quick",
    label: "Quick",
    hint: "Core BOLA + BFLA probes only",
  },
  {
    value: "balanced",
    label: "Balanced",
    hint: "Full authorization, workflow and business-logic matrix",
  },
  {
    value: "deep",
    label: "Deep",
    hint: "Adds an anonymous sweep across every object endpoint",
  },
];

export const IDENTITY_PRESETS = [
  { key: "user_a", label: "User A", role: "standard", tenant: "tenant-a", authMethod: "bearer" },
  { key: "user_b", label: "User B", role: "standard", tenant: "tenant-a", authMethod: "bearer" },
  { key: "user_c", label: "User C", role: "standard", tenant: "tenant-b", authMethod: "cookie" },
  { key: "manager", label: "Manager", role: "manager", tenant: "tenant-a", authMethod: "cookie" },
  { key: "admin", label: "Admin", role: "admin", tenant: "global", authMethod: "cookie" },
  { key: "anon", label: "Unauthenticated", role: "anonymous", tenant: "none", authMethod: "none" },
];

export const DISCOVERY_SOURCES = [
  { key: "browser", label: "Application crawl", detail: "Links, forms and pages fetched inside the allowlist" },
  { key: "openapi", label: "OpenAPI / Swagger probing", detail: "Well-known spec locations on the target, parsed for paths and parameters" },
  { key: "har", label: "HAR / Burp export", detail: "Import a capture from the Attack surface panel" },
  { key: "passive-js", label: "Passive JS extraction", detail: "Route literals pulled from bundles discovered while crawling" },
  { key: "forced-browsing", label: "Forced browsing", detail: "Bounded fetches of known pages, rate limited and budgeted" },
  { key: "manual", label: "Manual endpoint entry", detail: "Paste METHOD /path lines in the Attack surface panel" },
];

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

export function stageProgress(stage: number): number {
  if (stage < 0) return 0;
  return Math.min(100, Math.round(((stage + 1) / STAGES.length) * 100));
}
