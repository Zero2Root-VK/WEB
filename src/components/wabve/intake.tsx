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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import { useAction, useMutation, useQuery } from "convex/react";
import { KeyRound, Loader2, Trash2, Upload } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

const MAX_IMPORT_CHARS = 1_000_000;

const KINDS = [
  { value: "openapi", label: "OpenAPI / Swagger (JSON)", hint: "Paths, verbs and parameters from an API description" },
  { value: "har", label: "HAR capture", hint: "Browser or proxy export — real requests you already made" },
  { value: "js", label: "JavaScript bundle", hint: "Route literals extracted from a built asset" },
  { value: "html", label: "HTML page", hint: "Links, form actions and inline API references" },
  { value: "manual", label: "Manual list", hint: 'One endpoint per line: "GET /api/orders/{order_id}"' },
];

/**
 * Credential intake for one identity. The plaintext is sent once to the Node
 * action, encrypted there, and never returned — the UI only ever sees a mask.
 */
export function CredentialControl({
  engagementId,
  identityKey,
  identityLabel,
  authMethod,
  mask,
}: {
  engagementId: Id<"engagements">;
  identityKey: string;
  identityLabel: string;
  authMethod: string;
  mask?: string;
}) {
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState("");
  const [authType, setAuthType] = useState(authMethod === "cookie" ? "cookie" : "bearer");
  const [busy, setBusy] = useState(false);
  const setCredential = useAction(api.credentials.setIdentityCredential);

  const save = async () => {
    if (value.trim().length === 0) {
      toast.error("Paste a token or cookie value first");
      return;
    }
    setBusy(true);
    try {
      await setCredential({ engagementId, identityKey, authType, plaintext: value });
      toast.success(`Credential stored for ${identityLabel} — encrypted at rest`);
      setValue("");
      setOpen(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not store the credential");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        className="mt-3 h-7 w-full justify-center gap-1.5 font-mono text-[10px]"
        onClick={() => setOpen(true)}
      >
        <KeyRound className="size-3" />
        {mask ? `Stored · ${mask}` : "Set credential"}
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-base">Credential — {identityLabel}</DialogTitle>
            <DialogDescription className="font-mono text-[11px]">
              Encrypted with AES-256-GCM before it is stored. No query ever returns it; only the
              runner decrypts it, in memory, to authenticate a scoped request.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label className="font-mono text-[11px] uppercase text-muted-foreground">
                Credential type
              </Label>
              <Select value={authType} onValueChange={setAuthType}>
                <SelectTrigger className="font-mono text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="bearer">Bearer token (Authorization: Bearer …)</SelectItem>
                  <SelectItem value="cookie">Session cookie (Cookie: …)</SelectItem>
                </SelectContent>
              </Select>
              {authMethod !== "bearer" && authMethod !== "cookie" ? (
                <p className="text-[11px] text-amber-300/80">
                  This identity was created as “{authMethod}”. Live runs execute bearer tokens and
                  session cookies — paste the session value you captured from that flow.
                </p>
              ) : null}
            </div>

            <div className="space-y-2">
              <Label className="font-mono text-[11px] uppercase text-muted-foreground">
                Secret value
              </Label>
              <Input
                type="password"
                autoComplete="off"
                value={value}
                placeholder={authType === "bearer" ? "eyJhbGciOi…" : "session=…"}
                onChange={(event) => setValue(event.target.value)}
              />
              <p className="font-mono text-[10px] text-muted-foreground">
                {mask ? `Currently stored: ${mask} — saving replaces it.` : "Nothing stored yet."}
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button variant="ghost" size="sm" onClick={() => setOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button size="sm" onClick={save} disabled={busy}>
              {busy ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
              Encrypt &amp; store
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

/** Import an OpenAPI/HAR/JS/HTML artefact into the discovery registry. */
export function ArtifactImport({ engagementId }: { engagementId: Id<"engagements"> }) {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState("openapi");
  const [name, setName] = useState("");
  const [content, setContent] = useState("");
  const [busy, setBusy] = useState(false);
  const importArtifact = useMutation(api.pipeline.importArtifact);
  const deleteArtifact = useMutation(api.pipeline.deleteArtifact);
  const artifacts = useQuery(api.pipeline.listArtifacts, { engagementId });

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_IMPORT_CHARS) {
      toast.error("File is larger than 1 MB — split the capture first");
      return;
    }
    setContent(await file.text());
    setName((previous) => previous || file.name);
  };

  const submit = async () => {
    if (content.trim().length === 0) {
      toast.error("Paste or load an artefact first");
      return;
    }
    setBusy(true);
    try {
      const result = await importArtifact({
        engagementId,
        kind,
        name: name.trim() || KINDS.find((k) => k.value === kind)?.label || kind,
        content,
      });
      toast.success(`${result.count} endpoint(s) parsed into the registry`);
      setContent("");
      setName("");
      setOpen(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Import failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button variant="outline" size="sm" className="gap-1.5 font-mono text-[11px]" onClick={() => setOpen(true)}>
        <Upload className="size-3.5" />
        Import artefact
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="flex max-h-[85vh] flex-col gap-0 overflow-hidden p-0 sm:max-w-xl">
          <DialogHeader className="border-b border-border/60 px-6 py-4">
            <DialogTitle className="text-base">Discovery artefact</DialogTitle>
            <DialogDescription className="font-mono text-[11px]">
              Parsed on import — only the extracted endpoints are stored, never the raw dump.
            </DialogDescription>
          </DialogHeader>

          <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-6 py-5">
            <div className="space-y-2">
              <Label className="font-mono text-[11px] uppercase text-muted-foreground">Kind</Label>
              <Select value={kind} onValueChange={setKind}>
                <SelectTrigger className="font-mono text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {KINDS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-[11px] text-muted-foreground">
                {KINDS.find((k) => k.value === kind)?.hint}
              </p>
            </div>

            <div className="space-y-2">
              <Label className="font-mono text-[11px] uppercase text-muted-foreground">
                Load from file
              </Label>
              <Input
                type="file"
                accept={kind === "openapi" || kind === "har" ? ".json,.har" : ".js,.html,.txt,.md"}
                onChange={(event) => void onFile(event.target.files?.[0])}
                className="font-mono text-xs"
              />
            </div>

            <div className="space-y-2">
              <Label className="font-mono text-[11px] uppercase text-muted-foreground">
                …or paste
              </Label>
              <Textarea
                value={content}
                onChange={(event) => setContent(event.target.value)}
                placeholder={kind === "manual" ? "GET /api/orders/{order_id}\nDELETE /api/orders/{order_id}" : "{ \"openapi\": \"3.0.0\", … }"}
                className="min-h-40 font-mono text-[11px]"
              />
              <p className="font-mono text-[10px] text-muted-foreground">
                {content.length.toLocaleString()} / {MAX_IMPORT_CHARS.toLocaleString()} characters
              </p>
            </div>

            {artifacts && artifacts.length > 0 ? (
              <div className="space-y-2 border-t border-border/60 pt-4">
                <Label className="font-mono text-[11px] uppercase text-muted-foreground">
                  Imported
                </Label>
                {artifacts.map((artifact) => (
                  <div
                    key={artifact._id}
                    className="flex items-center gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2 font-mono text-[11px]"
                  >
                    <span className="truncate text-foreground/85">{artifact.name}</span>
                    <span className="ml-auto text-muted-foreground">{artifact.kind}</span>
                    <span className="tabular-nums text-primary">{artifact.endpointCount}</span>
                    <button
                      type="button"
                      className="text-muted-foreground transition-colors hover:text-red-400"
                      onClick={async () => {
                        await deleteArtifact({ artifactId: artifact._id });
                        toast.success("Artefact removed");
                      }}
                      aria-label={`Delete ${artifact.name}`}
                    >
                      <Trash2 className="size-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            ) : null}
          </div>

          <DialogFooter className="border-t border-border/60 px-6 py-4">
            <Button variant="ghost" size="sm" onClick={() => setOpen(false)} disabled={busy}>
              Close
            </Button>
            <Button size="sm" className="gap-1.5" onClick={submit} disabled={busy}>
              {busy ? <Loader2 className="size-4 animate-spin" /> : <Upload className="size-4" />}
              Parse into registry
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
