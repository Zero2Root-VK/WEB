"use node";

/**
 * Credential intake.
 *
 * This runs in the Node runtime because key material must come from the
 * server's environment — it can never reach the browser. The plaintext
 * credential exists only inside this function's memory: what gets written to
 * the database is an AES-256-GCM ciphertext plus a two-character mask.
 */

import { getAuthUserId } from "@convex-dev/auth/server";
import { v } from "convex/values";
import { api } from "./_generated/api";
import { internal } from "./_generated/api";
import { action } from "./_generated/server";
import { encryptSecret, maskSecret, requireSecretKey } from "./real/secrets";

export const setIdentityCredential = action({
  args: {
    engagementId: v.id("engagements"),
    identityKey: v.string(),
    authType: v.string(),
    /** Cookie header, bearer token, or password. Never logged, never persisted raw. */
    plaintext: v.string(),
  },
  handler: async (ctx, args) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) throw new Error("Not authenticated");

    if (args.plaintext.trim().length === 0) {
      throw new Error("Credential must not be empty");
    }
    if (args.plaintext.length > 8192) {
      throw new Error("Credential is too long");
    }

    // Ownership is checked against the same query the dashboard uses, so a
    // caller can only ever write credentials for an engagement they own.
    const owned = await ctx.runQuery(api.wabve.listEngagements, {});
    const engagement = owned.find((item) => item._id === args.engagementId);
    if (!engagement) throw new Error("Not found");

    const key = await requireSecretKey(process.env);
    const ciphertext = await encryptSecret(args.plaintext, key);
    const mask = maskSecret(args.plaintext);

    await ctx.runMutation(internal.wabve.storeIdentityCredential, {
      engagementId: args.engagementId,
      identityKey: args.identityKey,
      authType: args.authType,
      ciphertext,
      mask,
    });

    return { mask };
  },
});
