import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import type { Doc } from "@/convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import { OctagonX, RotateCw, Terminal } from "lucide-react";
import { useEffect, useRef } from "react";
import { STAGES, stageProgress } from "./shared";

const LEVEL_CLASS: Record<string, string> = {
  INFO: "text-sky-300",
  TEST: "text-foreground/85",
  VERIFY: "text-amber-300",
  WARN: "text-amber-400",
  CONFIRMED: "text-red-400",
};

export function ConsolePanel({
  engagement,
  events,
  onRerun,
  onKill,
}: {
  engagement: Doc<"engagements">;
  events: Doc<"events">[];
  onRerun: () => void;
  onKill: () => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const running = engagement.status === "running";

  useEffect(() => {
    const node = scrollRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [events.length]);

  const progress = stageProgress(engagement.stage);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Live test console</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Streamed from the deterministic engine. Every line is an audit-log record attached to this
            engagement.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 font-mono text-xs"
            onClick={onRerun}
            disabled={running}
          >
            <RotateCw className={cn("size-3.5", running && "animate-spin")} />
            {running ? "Running" : "Re-run"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 border-red-500/40 font-mono text-xs text-red-300 hover:bg-red-500/10"
            onClick={onKill}
            disabled={engagement.killSwitch}
          >
            <OctagonX className="size-3.5" />
            Kill switch
          </Button>
        </div>
      </div>

      <Card className="border-border/60 bg-card/40 py-0 shadow-none">
        <CardHeader className="px-5 py-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">Pipeline progress</CardTitle>
            <span className="font-mono text-[11px] text-muted-foreground">
              stage {Math.max(0, engagement.stage + 1)}/{STAGES.length} · {progress}%
            </span>
          </div>
          <Progress value={progress} className="mt-3 h-1.5" />
        </CardHeader>
        <CardContent className="grid gap-3 px-5 pb-5 sm:grid-cols-2 lg:grid-cols-4">
          {STAGES.map((stage, i) => {
            const state =
              engagement.stage > i ? "done" : engagement.stage === i ? "active" : "idle";
            return (
              <div key={stage.key} className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "size-1.5 rounded-full",
                      state === "done"
                        ? "bg-teal-400"
                        : state === "active"
                          ? "animate-pulse bg-primary"
                          : "bg-muted-foreground/40",
                    )}
                  />
                  <span
                    className={cn(
                      "font-mono text-[10px] tracking-wide uppercase",
                      state === "idle" ? "text-muted-foreground/60" : "text-foreground/85",
                    )}
                  >
                    {stage.label}
                  </span>
                </div>
                <Progress
                  value={state === "done" ? 100 : state === "active" ? 55 : 0}
                  className={cn(
                    "h-1 bg-muted/50",
                    state === "done" && "[&>[data-slot=progress-indicator]]:bg-teal-400",
                  )}
                />
              </div>
            );
          })}
        </CardContent>
      </Card>

      <Card className="border-border/60 bg-background/60 py-0 shadow-none">
        <CardHeader className="flex-row items-center gap-2 border-b border-border/60 px-4 py-2.5">
          <Terminal className="size-3.5 text-primary" />
          <CardTitle className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
            engine output
          </CardTitle>
          <span className="ml-auto flex items-center gap-2 font-mono text-[10px] text-muted-foreground">
            <span
              className={cn(
                "size-1.5 rounded-full",
                running ? "animate-pulse bg-primary" : "bg-muted-foreground/50",
              )}
            />
            {running ? "streaming" : engagement.status}
          </span>
        </CardHeader>
        <div ref={scrollRef} className="max-h-[26rem] overflow-y-auto px-4 py-3">
          {events.length === 0 ? (
            <p className="font-mono text-[11px] text-muted-foreground">
              No events yet. Start the engagement to stream the pipeline.
            </p>
          ) : (
            <div className="space-y-1">
              {events.map((event) => (
                <p key={event._id} className="font-mono text-[11px] leading-relaxed">
                  <span className="text-muted-foreground/60">
                    {new Date(event.ts).toLocaleTimeString([], { hour12: false })}
                  </span>{" "}
                  <span className={cn("w-20 inline-block", LEVEL_CLASS[event.level] ?? "text-foreground/80")}>
                    [{event.level}]
                  </span>{" "}
                  <span className="text-muted-foreground">({event.phase})</span>{" "}
                  <span className="text-foreground/85">{event.message}</span>
                </p>
              ))}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
