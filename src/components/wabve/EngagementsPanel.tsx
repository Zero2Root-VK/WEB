import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { Doc, Id } from "@/convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import { Plus, Trash2 } from "lucide-react";
import { EmptyState, PanelHeader, SEVERITY_CLASS, Tag } from "./shared";
import type { CoverageShape } from "./panels";

const STATUS_CLASS: Record<string, string> = {
  running: "border-primary/40 bg-primary/10 text-primary",
  complete: "border-teal-400/40 bg-teal-400/10 text-teal-300",
  halted: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  draft: "border-border/60 text-muted-foreground",
};

export function EngagementsPanel({
  engagements,
  selectedId,
  onSelect,
  onCreate,
  onDelete,
}: {
  engagements: Doc<"engagements">[];
  selectedId: Id<"engagements"> | null;
  onSelect: (id: Id<"engagements">) => void;
  onCreate: () => void;
  onDelete: (id: Id<"engagements">) => void;
}) {
  return (
    <div className="space-y-6">
      <PanelHeader
        title="Engagements"
        description="One engagement is one scoped authorization assessment: a target, a scope, a set of identities and a verification run."
        actions={
          <Button size="sm" className="gap-1.5 font-mono text-xs" onClick={onCreate}>
            <Plus className="size-3.5" />
            New engagement
          </Button>
        }
      />

      {engagements.length === 0 ? (
        <EmptyState
          title="No engagements yet"
          description="Create an engagement to declare a target, scope and the identities used to prove authorization."
        >
          <Button size="sm" className="gap-1.5 font-mono text-xs" onClick={onCreate}>
            <Plus className="size-3.5" />
            New engagement
          </Button>
        </EmptyState>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {engagements.map((engagement) => {
            const coverage = engagement.coverage as CoverageShape | undefined;
            const active = engagement._id === selectedId;
            return (
              <Card
                key={engagement._id}
                className={cn(
                  "border-border/60 bg-card/40 py-0 shadow-none transition-colors",
                  active && "border-primary/40 bg-primary/[0.04]",
                )}
              >
                <CardContent className="space-y-4 px-5 py-5">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium">{engagement.name}</p>
                      <p className="font-mono text-[11px] text-muted-foreground">
                        {engagement.target}
                      </p>
                    </div>
                    <Tag className={STATUS_CLASS[engagement.status] ?? STATUS_CLASS.draft}>
                      {engagement.status}
                    </Tag>
                  </div>

                  <div className="flex flex-wrap gap-1.5">
                    <Tag className="border-border/60 text-muted-foreground">
                      profile {engagement.profile}
                    </Tag>
                    <Tag className="border-border/60 text-muted-foreground">
                      {engagement.allowedPaths.join(" ") || "any path"}
                    </Tag>
                    <Tag className="border-border/60 text-muted-foreground">
                      {engagement.destructiveTesting ? "destructive approved" : "non-destructive"}
                    </Tag>
                  </div>

                  {coverage ? (
                    <div className="grid grid-cols-4 gap-2 border-t border-border/50 pt-3">
                      {[
                        ["endpoints", coverage.endpointsDiscovered],
                        ["probes", coverage.totalTests],
                        ["findings", coverage.findings],
                        ["blocked", coverage.blocked],
                      ].map(([label, value]) => (
                        <div key={String(label)}>
                          <p className="font-mono text-[9px] tracking-widest text-muted-foreground uppercase">
                            {label}
                          </p>
                          <p className="text-sm font-semibold tabular-nums">{value}</p>
                        </div>
                      ))}
                      <div className="col-span-4 flex flex-wrap gap-1.5 pt-1">
                        {(["critical", "high", "medium", "low"] as const)
                          .filter((severity) => (coverage[severity] ?? 0) > 0)
                          .map((severity) => (
                            <Tag key={severity} className={SEVERITY_CLASS[severity]}>
                              {coverage[severity]} {severity}
                            </Tag>
                          ))}
                      </div>
                    </div>
                  ) : (
                    <p className="border-t border-border/50 pt-3 font-mono text-[11px] text-muted-foreground">
                      No verification run yet.
                    </p>
                  )}

                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant={active ? "secondary" : "default"}
                      className="flex-1 font-mono text-xs"
                      onClick={() => onSelect(engagement._id)}
                    >
                      {active ? "Selected" : "Open console"}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-muted-foreground hover:text-red-300"
                      onClick={() => onDelete(engagement._id)}
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
