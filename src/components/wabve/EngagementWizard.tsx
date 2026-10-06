import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import { useMutation } from "convex/react";
import { Check, ChevronLeft, ChevronRight, Loader2, Play } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import {
  DISCOVERY_SOURCES,
  IDENTITY_PRESETS,
  PROFILES,
  Tag,
} from "./shared";

export interface IdentityDraft {
  key: string;
  label: string;
  role: string;
  tenant: string;
  authMethod: string;
}

const STEPS = [
  "Target",
  "Scope",
  "Authentication",
  "Identities",
  "Discovery",
  "Testing profile",
  "Safety controls",
  "Start",
];

const AUTH_METHODS = [
  { value: "bearer", label: "Bearer token", hint: "Authorization: Bearer <token>" },
  { value: "cookie", label: "Session cookie", hint: "Cookie: session=..." },
  { value: "password", label: "Username / password", hint: "Configured login flow" },
  { value: "har", label: "Captured browser session", hint: "HAR / Burp import" },
  { value: "custom", label: "Custom authentication", hint: "Login URL, method, parameters, CSRF" },
];

export const REFERENCE_PRESET = {
  name: "Acme Staging — Authorization Review",
  target: "https://staging.acme.test",
  allowedHosts: ["staging.acme.test"],
  allowedPaths: ["/api/"],
  rateLimit: 5,
  requestBudget: 2000,
  profile: "balanced",
  mode: "demo" as const,
  identities: IDENTITY_PRESETS as IdentityDraft[],
};

export function EngagementWizard({
  open,
  onOpenChange,
  onCreated,
  initial,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated?: (id: Id<"engagements">) => void;
  initial?: typeof REFERENCE_PRESET;
}) {
  const createEngagement = useMutation(api.wabve.createEngagement);
  const startEngagement = useMutation(api.wabve.startEngagement);

  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState(initial?.name ?? REFERENCE_PRESET.name);
  const [target, setTarget] = useState(initial?.target ?? REFERENCE_PRESET.target);
  const [allowedPaths, setAllowedPaths] = useState(
    (initial?.allowedPaths ?? REFERENCE_PRESET.allowedPaths).join(", "),
  );
  const [allowedHosts, setAllowedHosts] = useState(
    (initial?.allowedHosts ?? REFERENCE_PRESET.allowedHosts).join(", "),
  );
  const [rateLimit, setRateLimit] = useState(initial?.rateLimit ?? 5);
  const [requestBudget, setRequestBudget] = useState(initial?.requestBudget ?? 2000);
  const [authMethod, setAuthMethod] = useState("bearer");
  const [identities, setIdentities] = useState<IdentityDraft[]>(
    initial?.identities ?? (IDENTITY_PRESETS as IdentityDraft[]),
  );
  const [sources, setSources] = useState<string[]>([
    "browser",
    "openapi",
    "passive-js",
    "forced-browsing",
  ]);
  const [profile, setProfile] = useState(initial?.profile ?? "balanced");
  const [mode, setMode] = useState<string>(initial?.mode ?? "live");
  const [destructiveTesting, setDestructiveTesting] = useState(false);
  const [dryRun, setDryRun] = useState(false);
  const [startNow, setStartNow] = useState(true);

  const hostList = useMemo(
    () => allowedHosts.split(",").map((h) => h.trim()).filter(Boolean),
    [allowedHosts],
  );
  const pathList = useMemo(
    () => allowedPaths.split(",").map((p) => p.trim()).filter(Boolean),
    [allowedPaths],
  );

  const toggleIdentity = (key: string) => {
    setIdentities((prev) =>
      prev.some((i) => i.key === key)
        ? prev.filter((i) => i.key !== key)
        : [
            ...prev,
            (IDENTITY_PRESETS.find((p) => p.key === key) ?? IDENTITY_PRESETS[0]) as IdentityDraft,
          ],
    );
  };

  const toggleSource = (key: string) => {
    setSources((prev) => (prev.includes(key) ? prev.filter((s) => s !== key) : [...prev, key]));
  };

  const submit = async () => {
    if (identities.length < 2) {
      toast.error("Add at least two identities so authorization can be compared.");
      setStep(3);
      return;
    }
    if (mode === "live") {
      let valid = false;
      try {
        const url = new URL(target.trim());
        valid =
          (url.protocol === "http:" || url.protocol === "https:") &&
          hostList.length > 0 &&
          rateLimit >= 1 &&
          requestBudget >= 10;
      } catch {
        valid = false;
      }
      if (!valid) {
        toast.error(
          "Live mode needs a valid http(s) target, at least one allowed host, a rate limit ≥ 1 and a budget ≥ 10.",
        );
        setStep(0);
        return;
      }
    }
    setBusy(true);
    try {
      const id = await createEngagement({
        name: name.trim() || "Untitled engagement",
        target: target.trim(),
        allowedHosts: hostList,
        allowedPaths: pathList,
        rateLimit,
        requestBudget,
        destructiveTesting,
        dryRun,
        profile,
        mode,
        discoverySources: sources,
        // The anonymous identity stays anonymous regardless of the auth
        // method selected for the rest of the matrix.
        identities: identities.map((i) => ({
          ...i,
          authMethod: i.role === "anonymous" ? "none" : authMethod,
        })),
      });
      onCreated?.(id);
      onOpenChange(false);
      if (mode === "demo" && startNow) {
        await startEngagement({ engagementId: id });
        toast.success("Demo lab created and running");
      } else if (mode === "live") {
        toast.success("Live engagement created — add identity credentials, then press Run");
      } else {
        toast.success("Engagement saved as a draft");
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not create the engagement");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[90vh] flex-col gap-0 overflow-hidden p-0 sm:max-w-2xl">
        <DialogHeader className="border-b border-border/60 px-6 py-4">
          <DialogTitle className="text-base">New engagement</DialogTitle>
          <DialogDescription className="font-mono text-[11px]">
            Step {step + 1} of {STEPS.length} — {STEPS[step]}
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-wrap gap-1 border-b border-border/60 bg-muted/20 px-6 py-3">
          {STEPS.map((label, i) => (
            <button
              key={label}
              type="button"
              onClick={() => setStep(i)}
              className={cn(
                "rounded-full border px-2.5 py-1 font-mono text-[10px] tracking-wide uppercase transition-colors",
                i === step
                  ? "border-primary/50 bg-primary/15 text-primary"
                  : i < step
                    ? "border-border/60 bg-background/40 text-foreground/70"
                    : "border-border/40 text-muted-foreground",
              )}
            >
              {i < step ? <Check className="mr-1 inline size-3" /> : null}
              {label}
            </button>
          ))}
        </div>

        <ScrollArea className="min-h-0 flex-1">
          <div className="space-y-5 px-6 py-5">
            {step === 0 ? (
              <>
                <Field label="Engagement name">
                  <Input value={name} onChange={(e) => setName(e.target.value)} />
                </Field>
                <Field
                  label="Target base URL"
                  hint="Where the engine sends real requests in live mode; also used for reporting."
                >
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} />
                </Field>
                <div className="space-y-2">
                  <Label className="font-mono text-[11px] tracking-wide text-muted-foreground uppercase">
                    Mode
                  </Label>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <ModeCard
                      active={mode === "live"}
                      onClick={() => setMode("live")}
                      title="Live target"
                      detail="Real HTTP requests against the allowlisted host, behind the scope guard, rate limiter and budget."
                    />
                    <ModeCard
                      active={mode === "demo"}
                      onClick={() => setMode("demo")}
                      title="Demo lab"
                      detail="Modelled application with a known flaw — no network traffic. Evaluating the product end to end."
                    />
                  </div>
                </div>
              </>
            ) : null}

            {step === 1 ? (
              <>
                <Field label="Allowed hosts" hint="Comma separated. The engine blocks every other host.">
                  <Input value={allowedHosts} onChange={(e) => setAllowedHosts(e.target.value)} />
                </Field>
                <Field label="Allowed paths" hint="Comma separated prefixes. Anything else is refused before dispatch.">
                  <Input value={allowedPaths} onChange={(e) => setAllowedPaths(e.target.value)} />
                </Field>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="Rate limit (requests / second)">
                    <Input
                      type="number"
                      min={1}
                      max={100}
                      value={rateLimit}
                      onChange={(e) => setRateLimit(Number(e.target.value) || 1)}
                    />
                  </Field>
                  <Field label="Request budget">
                    <Input
                      type="number"
                      min={10}
                      max={100000}
                      value={requestBudget}
                      onChange={(e) => setRequestBudget(Number(e.target.value) || 100)}
                    />
                  </Field>
                </div>
              </>
            ) : null}

            {step === 2 ? (
              <div className="space-y-2">
                {AUTH_METHODS.map((method) => (
                  <button
                    key={method.value}
                    type="button"
                    onClick={() => setAuthMethod(method.value)}
                    className={cn(
                      "flex w-full items-start justify-between gap-4 rounded-md border px-4 py-3 text-left transition-colors",
                      authMethod === method.value
                        ? "border-primary/50 bg-primary/10"
                        : "border-border/60 bg-background/40 hover:border-border",
                    )}
                  >
                    <div>
                      <p className="text-sm font-medium">{method.label}</p>
                      <p className="font-mono text-[11px] text-muted-foreground">{method.hint}</p>
                    </div>
                    {authMethod === method.value ? (
                      <Check className="mt-0.5 size-4 shrink-0 text-primary" />
                    ) : null}
                  </button>
                ))}
              </div>
            ) : null}

            {step === 3 ? (
              <>
                <p className="text-xs text-muted-foreground">
                  Every probe is attributed to one of these identities. Secrets are never stored —
                  only a redacted hint.
                </p>
                <div className="space-y-2">
                  {IDENTITY_PRESETS.map((preset) => {
                    const active = identities.some((i) => i.key === preset.key);
                    return (
                      <button
                        key={preset.key}
                        type="button"
                        onClick={() => toggleIdentity(preset.key)}
                        className={cn(
                          "flex w-full items-center gap-3 rounded-md border px-4 py-3 text-left transition-colors",
                          active
                            ? "border-primary/40 bg-primary/[0.07]"
                            : "border-border/60 bg-background/40",
                        )}
                      >
                        <span
                          className={cn(
                            "flex size-4 shrink-0 items-center justify-center rounded border",
                            active ? "border-primary bg-primary text-primary-foreground" : "border-border",
                          )}
                        >
                          {active ? <Check className="size-3" /> : null}
                        </span>
                        <span className="flex-1 text-sm font-medium">{preset.label}</span>
                        <Tag>{preset.role}</Tag>
                        <Tag className="border-border/60 text-muted-foreground">{preset.tenant}</Tag>
                      </button>
                    );
                  })}
                </div>
              </>
            ) : null}

            {step === 4 ? (
              <div className="space-y-2">
                {DISCOVERY_SOURCES.map((source) => {
                  const active = sources.includes(source.key);
                  return (
                    <button
                      key={source.key}
                      type="button"
                      onClick={() => toggleSource(source.key)}
                      className={cn(
                        "flex w-full items-center gap-3 rounded-md border px-4 py-3 text-left transition-colors",
                        active ? "border-primary/40 bg-primary/[0.07]" : "border-border/60 bg-background/40",
                      )}
                    >
                      <span
                        className={cn(
                          "flex size-4 shrink-0 items-center justify-center rounded border",
                          active ? "border-primary bg-primary text-primary-foreground" : "border-border",
                        )}
                      >
                        {active ? <Check className="size-3" /> : null}
                      </span>
                      <span className="flex-1">
                        <span className="block text-sm font-medium">{source.label}</span>
                        <span className="block font-mono text-[11px] text-muted-foreground">
                          {source.detail}
                        </span>
                      </span>
                    </button>
                  );
                })}
              </div>
            ) : null}

            {step === 5 ? (
              <div className="space-y-2">
                {PROFILES.map((item) => (
                  <button
                    key={item.value}
                    type="button"
                    onClick={() => setProfile(item.value)}
                    className={cn(
                      "w-full rounded-md border px-4 py-3 text-left transition-colors",
                      profile === item.value
                        ? "border-primary/50 bg-primary/10"
                        : "border-border/60 bg-background/40",
                    )}
                  >
                    <p className="text-sm font-medium">{item.label}</p>
                    <p className="font-mono text-[11px] text-muted-foreground">{item.hint}</p>
                  </button>
                ))}
              </div>
            ) : null}

            {step === 6 ? (
              <div className="space-y-3">
                <ToggleRow
                  label="Approve destructive testing"
                  hint="Required before any probe that irreversibly removes a record can run."
                  checked={destructiveTesting}
                  onChange={setDestructiveTesting}
                />
                <ToggleRow
                  label="Dry-run mode"
                  hint="Simulate state mutations without applying them to the modelled target."
                  checked={dryRun}
                  onChange={setDryRun}
                />
                <div className="rounded-md border border-border/60 bg-background/40 px-4 py-3 font-mono text-[11px] text-muted-foreground">
                  Kill switch, audit logging and secret redaction are always on.
                </div>
              </div>
            ) : null}

            {step === 7 ? (
              <div className="space-y-4">
                <ToggleRow
                  label="Start the demo lab immediately"
                  hint="Live engagements start from the dashboard once credentials are stored."
                  checked={startNow}
                  onChange={setStartNow}
                />
                <div className="rounded-md border border-border/60 bg-background/40 p-4 font-mono text-[11px]">
                  {                    [["name", name],
                    ["mode", mode === "live" ? "live target" : "demo lab"],
                    ["target", target],
                    ["hosts", hostList.join(", ") || "—"],
                    ["paths", pathList.join(", ") || "any"],
                    ["rate", `${rateLimit}/s`],
                    ["budget", String(requestBudget)],
                    ["auth", authMethod],
                    ["identities", String(identities.length)],
                    ["discovery", sources.join(", ") || "—"],
                    ["profile", profile],
                    ["destructive", destructiveTesting ? "approved" : "blocked"],
                  ].map(([k, v]) => (
                    <div key={k} className="flex gap-3 py-0.5">
                      <span className="w-24 shrink-0 text-muted-foreground uppercase">{k}</span>
                      <span className="text-foreground/85">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </ScrollArea>

        <DialogFooter className="flex-row items-center justify-between border-t border-border/60 px-6 py-4 sm:justify-between">
          <Button
            variant="ghost"
            size="sm"
            className="gap-1.5"
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            disabled={step === 0 || busy}
          >
            <ChevronLeft className="size-4" />
            Back
          </Button>
          {step < STEPS.length - 1 ? (
            <Button size="sm" className="gap-1.5" onClick={() => setStep((s) => s + 1)}>
              Next
              <ChevronRight className="size-4" />
            </Button>
          ) : (
            <Button size="sm" className="gap-1.5" onClick={submit} disabled={busy}>
              {busy ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
              {startNow ? "Create & run" : "Save draft"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <Label className="font-mono text-[11px] tracking-wide text-muted-foreground uppercase">
        {label}
      </Label>
      {children}
      {hint ? <p className="text-[11px] text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

function ModeCard({
  active,
  onClick,
  title,
  detail,
}: {
  active: boolean;
  onClick: () => void;
  title: string;
  detail: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded-md border px-4 py-3 text-left transition-colors",
        active ? "border-primary/50 bg-primary/10" : "border-border/60 bg-background/40 hover:border-border",
      )}
    >
      <p className="text-sm font-medium">{title}</p>
      <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{detail}</p>
    </button>
  );
}

function ToggleRow({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-4 rounded-md border border-border/60 bg-background/40 px-4 py-3">
      <div>
        <p className="text-sm font-medium">{label}</p>
        <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{hint}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}
