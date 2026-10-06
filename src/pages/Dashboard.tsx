import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ConsolePanel } from "@/components/wabve/ConsolePanel";
import { EngagementsPanel } from "@/components/wabve/EngagementsPanel";
import {
  EngagementWizard,
  REFERENCE_PRESET,
} from "@/components/wabve/EngagementWizard";
import { FindingsPanel } from "@/components/wabve/FindingsPanel";
import { AuthzGraph, WorkflowPanel } from "@/components/wabve/graphs";
import {
  AttackSurfacePanel,
  IdentitiesPanel,
  OverviewPanel,
  readCoverage,
} from "@/components/wabve/panels";
import { ReportsPanel } from "@/components/wabve/ReportsPanel";
import { SEVERITY_CLASS, STAGES, Tag } from "@/components/wabve/shared";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import { useAuth } from "@/hooks/use-auth";
import { cn } from "@/lib/utils";
import { useMutation, useQuery } from "convex/react";
import {
  Activity,
  GitBranch,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Network,
  Play,
  Sigma,
  Target,
  Users,
} from "lucide-react";
import type { ComponentType } from "react";
import { useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";

type SectionKey =
  | "overview"
  | "engagements"
  | "identities"
  | "surface"
  | "authz"
  | "workflow"
  | "console"
  | "findings"
  | "reports";

const NAV: Array<{ key: SectionKey; label: string; icon: ComponentType<{ className?: string }> }> = [
  { key: "overview", label: "Overview", icon: LayoutDashboard },
  { key: "engagements", label: "Engagements", icon: Target },
  { key: "identities", label: "Identities", icon: Users },
  { key: "surface", label: "Attack surface", icon: Network },
  { key: "authz", label: "Authorization graph", icon: Activity },
  { key: "workflow", label: "Workflow graph", icon: GitBranch },
  { key: "console", label: "Live console", icon: ListChecks },
  { key: "findings", label: "Findings", icon: ListChecks },
  { key: "reports", label: "Reports", icon: Sigma },
];

export default function Dashboard() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();

  const engagements = useQuery(api.wabve.listEngagements);
  const [selectedId, setSelectedId] = useState<Id<"engagements"> | null>(null);
  const [section, setSection] = useState<SectionKey>("overview");
  const [wizardOpen, setWizardOpen] = useState(false);

  const createEngagement = useMutation(api.wabve.createEngagement);
  const startEngagement = useMutation(api.wabve.startEngagement);
  const deleteEngagement = useMutation(api.wabve.deleteEngagement);
  const setKillSwitch = useMutation(api.wabve.setKillSwitch);

  // Selection is derived during render rather than synced in an effect: the
  // first engagement is active until the operator picks another one, and a
  // deleted selection falls back to the next available engagement.
  const activeId =
    selectedId && engagements?.some((e) => e._id === selectedId)
      ? selectedId
      : (engagements?.[0]?._id ?? null);

  const engagement = engagements?.find((e) => e._id === activeId) ?? null;

  const identities = useQuery(
    api.wabve.listIdentities,
    activeId ? { engagementId: activeId } : "skip",
  );
  const endpoints = useQuery(
    api.wabve.listEndpoints,
    activeId ? { engagementId: activeId } : "skip",
  );
  const objects = useQuery(api.wabve.listObjects, activeId ? { engagementId: activeId } : "skip");
  const tests = useQuery(api.wabve.listTests, activeId ? { engagementId: activeId } : "skip");
  const findings = useQuery(
    api.wabve.listFindings,
    activeId ? { engagementId: activeId } : "skip",
  );
  const events = useQuery(api.wabve.listEvents, activeId ? { engagementId: activeId } : "skip");
  const credentialMasks = useQuery(
    api.pipeline.listCredentialMasks,
    activeId ? { engagementId: activeId } : "skip",
  );

  const coverage = engagement ? readCoverage(engagement) : null;
  const running = engagement?.status === "running";

  const handleSignOut = async () => {
    await signOut();
    navigate("/");
  };

  const handleLoadReference = async () => {
    try {
      const id = await createEngagement({ ...REFERENCE_PRESET, destructiveTesting: false, dryRun: false });
      setSelectedId(id);
      setSection("console");
      await startEngagement({ engagementId: id });
      toast.success("Reference engagement created and running");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not create the engagement");
    }
  };

  const handleRerun = async () => {
    if (!activeId) return;
    await startEngagement({ engagementId: activeId });
    toast.success("Verification engine restarted");
  };

  const handleKill = async () => {
    if (!activeId) return;
    await setKillSwitch({ engagementId: activeId, value: true });
    toast.warning("Kill switch engaged");
  };

  const handleDelete = async (id: Id<"engagements">) => {
    await deleteEngagement({ engagementId: id });
    if (activeId === id) setSelectedId(null);
    toast.success("Engagement deleted");
  };

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      {/* sidebar */}
      <aside className="hidden w-60 shrink-0 flex-col border-r border-border/60 bg-sidebar lg:flex">
        <div className="flex h-14 items-center gap-2.5 border-b border-border/60 px-5">
          <div className="flex size-8 items-center justify-center rounded-md border border-primary/40 bg-primary/10">
            <Sigma className="size-4 text-primary" />
          </div>
          <div className="leading-none">
            <span className="font-mono text-sm font-semibold tracking-[0.2em]">WABVE</span>
            <p className="mt-0.5 font-mono text-[9px] tracking-[0.14em] text-muted-foreground uppercase">
              operator console
            </p>
          </div>
        </div>

        <nav className="flex-1 space-y-1 p-3">
          {NAV.map((item) => (
            <button
              key={item.key}
              type="button"
              onClick={() => setSection(item.key)}
              className={cn(
                "flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-left font-mono text-[11px] tracking-wide uppercase transition-colors",
                section === item.key
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
              )}
            >
              <item.icon className="size-4 shrink-0" />
              {item.label}
              {item.key === "findings" && (findings?.length ?? 0) > 0 ? (
                <span className="ml-auto rounded-full bg-red-500/20 px-1.5 font-mono text-[10px] text-red-300">
                  {findings?.length}
                </span>
              ) : null}
            </button>
          ))}
        </nav>

        <div className="space-y-2 border-t border-border/60 p-3">
          <p className="truncate px-2 font-mono text-[10px] text-muted-foreground">
            {user?.name ?? user?.email ?? "signed in"}
          </p>
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-start gap-2 font-mono text-[11px]"
            onClick={handleSignOut}
          >
            <LogOut className="size-3.5" />
            Sign out
          </Button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        {/* header */}
        <header className="sticky top-0 z-20 border-b border-border/60 bg-background/85 backdrop-blur">
          <div className="flex flex-wrap items-center gap-3 px-4 py-3 sm:px-6">
            <div className="flex items-center gap-2 lg:hidden">
              <Sigma className="size-4 text-primary" />
              <span className="font-mono text-xs tracking-[0.2em]">WABVE</span>
            </div>

            {engagements && engagements.length > 0 ? (
              <Select
                value={activeId ?? ""}
                onValueChange={(value) => setSelectedId(value as Id<"engagements">)}
              >
                <SelectTrigger className="h-8 w-full max-w-xs font-mono text-xs sm:w-64">
                  <SelectValue placeholder="Select an engagement" />
                </SelectTrigger>
                <SelectContent>
                  {engagements.map((item) => (
                    <SelectItem key={item._id} value={item._id} className="font-mono text-xs">
                      {item.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : null}

            {engagement ? (
              <div className="flex flex-wrap items-center gap-1.5">
                <Badge
                  variant="outline"
                  className={cn(
                    "font-mono text-[10px] uppercase",
                    running
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : engagement.status === "complete"
                        ? "border-teal-400/40 bg-teal-400/10 text-teal-300"
                        : "border-border/60 text-muted-foreground",
                  )}
                >
                  {running ? (
                    <span className="mr-1.5 inline-block size-1.5 animate-pulse rounded-full bg-primary" />
                  ) : null}
                  {engagement.status}
                </Badge>
                <Tag
                  className={
                    (engagement.mode ?? "live") === "demo"
                      ? "border-amber-500/40 text-amber-300"
                      : "border-teal-400/40 text-teal-300"
                  }
                >
                  {(engagement.mode ?? "live") === "demo" ? "demo lab" : "live target"}
                </Tag>
                {coverage ? (
                  <>
                    {(["critical", "high", "medium"] as const)
                      .filter((severity) => (coverage[severity] ?? 0) > 0)
                      .map((severity) => (
                        <Tag key={severity} className={SEVERITY_CLASS[severity]}>
                          {coverage[severity]} {severity}
                        </Tag>
                      ))}
                  </>
                ) : null}
              </div>
            ) : null}

            <div className="ml-auto flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                className="gap-1.5 font-mono text-xs"
                onClick={() => setWizardOpen(true)}
              >
                New
              </Button>
              {engagement ? (
                <Button
                  size="sm"
                  className="gap-1.5 font-mono text-xs"
                  onClick={handleRerun}
                  disabled={running}
                >
                  <Play className="size-3.5" />
                  {running ? "Running" : "Run"}
                </Button>
              ) : null}
              <Button
                size="sm"
                variant="ghost"
                className="gap-1.5 font-mono text-xs lg:hidden"
                onClick={handleSignOut}
              >
                <LogOut className="size-3.5" />
              </Button>
            </div>
          </div>

          {/* mobile nav */}
          <div className="flex gap-1 overflow-x-auto border-t border-border/60 px-3 py-2 lg:hidden">
            {NAV.map((item) => (
              <button
                key={item.key}
                type="button"
                onClick={() => setSection(item.key)}
                className={cn(
                  "shrink-0 rounded-full border px-3 py-1 font-mono text-[10px] tracking-wide uppercase transition-colors",
                  section === item.key
                    ? "border-primary/50 bg-primary/10 text-primary"
                    : "border-border/60 text-muted-foreground",
                )}
              >
                {item.label}
              </button>
            ))}
          </div>
        </header>

        <main className="flex-1 px-4 py-6 sm:px-6 sm:py-8">
          {engagements === undefined ? (
            <p className="font-mono text-xs text-muted-foreground">Loading engagements…</p>
          ) : engagements.length === 0 ? (
            <Onboarding
              onCreate={() => setWizardOpen(true)}
              onLoadReference={handleLoadReference}
            />
          ) : section === "engagements" ? (
            <EngagementsPanel
              engagements={engagements}
              selectedId={activeId}
              onSelect={(id) => {
                setSelectedId(id);
                setSection("overview");
              }}
              onCreate={() => setWizardOpen(true)}
              onDelete={handleDelete}
            />
          ) : !engagement ? (
            <p className="font-mono text-xs text-muted-foreground">Select an engagement.</p>
          ) : (
            <>
              {section === "overview" ? (
                <OverviewPanel
                  engagement={engagement}
                  endpoints={endpoints ?? []}
                  identities={identities ?? []}
                  tests={tests ?? []}
                  findings={findings ?? []}
                />
              ) : null}
              {section === "identities" ? (
                <IdentitiesPanel
                  identities={identities ?? []}
                  engagementId={activeId ?? undefined}
                  credentials={credentialMasks ?? []}
                />
              ) : null}
              {section === "surface" ? (
                <AttackSurfacePanel
                  endpoints={endpoints ?? []}
                  tests={tests ?? []}
                  objects={objects ?? []}
                  engagementId={activeId ?? undefined}
                />
              ) : null}
              {section === "authz" ? (
                <AuthzGraph tests={tests ?? []} endpoints={endpoints ?? []} />
              ) : null}
              {section === "workflow" ? <WorkflowPanel tests={tests ?? []} /> : null}
              {section === "console" ? (
                <ConsolePanel
                  engagement={engagement}
                  events={events ?? []}
                  onRerun={handleRerun}
                  onKill={handleKill}
                />
              ) : null}
              {section === "findings" ? <FindingsPanel findings={findings ?? []} /> : null}
              {section === "reports" ? (
                <ReportsPanel
                  engagement={engagement}
                  findings={findings ?? []}
                  tests={tests ?? []}
                  endpoints={endpoints ?? []}
                  identities={identities ?? []}
                  objects={objects ?? []}
                  events={events ?? []}
                />
              ) : null}
            </>
          )}
        </main>
      </div>

      <EngagementWizard
        open={wizardOpen}
        onOpenChange={setWizardOpen}
        onCreated={(id) => {
          setSelectedId(id);
          setSection("console");
        }}
      />
    </div>
  );
}

function Onboarding({
  onCreate,
  onLoadReference,
}: {
  onCreate: () => void;
  onLoadReference: () => void;
}) {
  return (
    <div className="mx-auto max-w-3xl py-6">
      <p className="font-mono text-[10px] tracking-[0.24em] text-muted-foreground uppercase">
        <span className="mr-2 text-primary">/</span>
        No engagements yet
      </p>
      <h1 className="mt-4 text-2xl leading-tight font-semibold tracking-tight text-balance sm:text-3xl">
        Model the application. Prove the authorization gap.
      </h1>
      <p className="mt-4 max-w-2xl text-sm leading-6 text-muted-foreground text-pretty">
        WABVE builds an application and authorization model, generates a test
        matrix across identities and objects, executes every probe behind a scope
        guard, and reports a finding only when a reference policy disagrees with
        the target <em>and</em> the state delta proves it.
      </p>

      <div className="mt-8 flex flex-wrap items-center gap-x-6 gap-y-3">
        <Button className="gap-2 font-mono text-xs" onClick={onCreate}>
          <Target className="size-4" />
          Create an engagement
        </Button>
        <button
          type="button"
          onClick={onLoadReference}
          className="font-mono text-[11px] tracking-[0.12em] text-muted-foreground uppercase underline decoration-border underline-offset-[6px] transition-colors hover:text-foreground"
        >
          Load the reference engagement
        </button>
      </div>

      <ol className="mt-10 border-t border-border/70">
        {STAGES.map((stage, i) => (
          <li
            key={stage.key}
            className="flex flex-wrap items-baseline gap-x-5 gap-y-1 border-b border-border/70 py-3"
          >
            <span className="font-mono text-[10px] text-primary tabular-nums">
              {String(i + 1).padStart(2, "0")}
            </span>
            <span className="w-28 shrink-0 text-sm font-medium">{stage.label}</span>
            <span className="font-mono text-[11px] leading-5 text-muted-foreground">
              {STAGE_DETAIL[stage.key] ?? ""}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

const STAGE_DETAIL: Record<string, string> = {
  scope: "Host and path allowlist, rate limit, budget, kill switch",
  discovery: "Unified endpoint registry from every discovery source",
  identity: "Session verification for each declared identity",
  model: "Objects, roles, tenants and entity types",
  matrix: "One actor × one object × one endpoint per probe",
  execution: "Scope-guarded probes with full request capture",
  findings: "Reference vs target vs state delta → verdict",
  report: "HTML, PDF, JSON, Markdown, SARIF and CSV artefacts",
};
