import { describe, expect, it } from "vitest";
import { indianPii, otpSafety, paymentVerification, verhoeffDigit, verhoeffValid } from "../src/checks/bharat";
import { secretsInRepo } from "../src/checks/secrets";
import { applyPatch } from "../src/apply";
import { guardPatch } from "../src/diffGuard";
import type { RepoFile } from "../src/types";

const repo = (files: RepoFile[]) => ({ repo: { name: "shop", files } });
/** A checksum-valid 12-digit number built at runtime, so no real-looking Aadhaar is committed. */
const fakeAadhaar = (prefix = "23456789012") => prefix + verhoeffDigit(prefix);

describe("Verhoeff (Aadhaar checksum)", () => {
  it("matches the published example and rejects a one-digit change", () => {
    expect(verhoeffValid("2363")).toBe(true); // standard Verhoeff example: 236 -> check digit 3
    expect(verhoeffValid("2364")).toBe(false);
    const a = fakeAadhaar();
    expect(verhoeffValid(a)).toBe(true);
    expect(verhoeffValid(a.slice(0, 11) + ((Number(a[11]) + 1) % 10))).toBe(false);
  });
});

describe("payment-verification", () => {
  const unverified = [
    'app.post("/api/pay/verify", (req, res) => {',
    "  const { razorpay_payment_id, razorpay_order_id } = req.body;",
    "  orders.markPaid(razorpay_order_id, razorpay_payment_id);",
    "  res.json({ ok: true });",
    "});",
  ].join("\n");

  it("flags a Razorpay handler that never checks the signature", async () => {
    const f = await paymentVerification.detect(repo([{ path: "server.js", content: unverified }]));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", line: 2, title: expect.stringContaining("Razorpay") });
  });

  it("passes when the handler verifies with the SDK helper", async () => {
    const sdk = unverified.replace(
      "orders.markPaid",
      "if (!validatePaymentVerification({ order_id: razorpay_order_id, payment_id: razorpay_payment_id }, req.body.razorpay_signature, secret)) return res.sendStatus(400);\n  orders.markPaid",
    );
    expect(await paymentVerification.detect(repo([{ path: "server.js", content: sdk }]))).toEqual([]);
  });

  it("flags a UPI/Paytm status trusted from the request", async () => {
    const cb = 'app.post("/paytm/callback", (req, res) => { if (req.body.STATUS === "TXN_SUCCESS") orders.markPaid(req.body.ORDERID); res.redirect("/thanks"); });';
    const f = await paymentVerification.detect(repo([{ path: "routes/pay.js", content: cb }]));
    expect(f.map((x) => x.title)).toEqual(["Payment status taken from the request instead of the gateway"]);
  });

  it("adds the helper and wires it into the route with added lines only, so the check passes", async () => {
    const withRequire = `const express = require('express');\nconst orders = require('./orders');\n${unverified}`;
    const ctx = repo([{ path: "package.json", content: '{"name":"shop"}' }, { path: "routes/pay.js", content: withRequire }]);
    const patch = await paymentVerification.fix!(ctx, await paymentVerification.detect(ctx));
    expect(patch?.class).toBe("additive");
    const guard = guardPatch(ctx.repo, patch!);
    expect(guard.ok).toBe(true);
    expect(guard.removed).toBe(0);
    const helper = patch!.edits[0].kind === "create" ? patch!.edits[0].content : "";
    expect(helper).toContain('crypto.createHmac("sha256", secret)');
    expect(helper).toContain("timingSafeEqual");
    const fixed = applyPatch(ctx.repo, patch!);
    const route = fixed.files.find((f) => f.path === "routes/pay.js")!.content.split("\n");
    expect(route.at(2)).toBe("const verifyRazorpaySignature = require('../lib/verifyRazorpaySignature');"); // under the existing requires
    expect(route.at(4)).toBe("  if (!verifyRazorpaySignature(req.body)) { res.status(400).json({ error: 'payment not verified' }); return; }");
    expect(route.at(5)).toContain("razorpay_payment_id"); // guard sits right before the line that reads the id
    expect(await paymentVerification.detect({ repo: fixed })).toEqual([]);
  });

  it("writes ES module code for type: module projects", async () => {
    const ctx = repo([{ path: "package.json", content: '{"type":"module"}' }, { path: "server.js", content: `import express from "express";\n${unverified}` }]);
    const patch = await paymentVerification.fix!(ctx, await paymentVerification.detect(ctx));
    const helper = patch!.edits[0].kind === "create" ? patch!.edits[0].content : "";
    expect(helper).toContain('import crypto from "node:crypto"');
    expect(helper).toContain("export default verifyRazorpaySignature");
    const route = patch!.edits[1].kind === "modify" ? patch!.edits[1].after : "";
    expect(route.split("\n").at(1)).toBe('import verifyRazorpaySignature from "./lib/verifyRazorpaySignature.js";');
  });
});

describe("indian-pii", () => {
  it("finds a checksum-valid Aadhaar (named or 4-4-4 formatted) and masks it", async () => {
    const a = fakeAadhaar();
    const spaced = `${a.slice(0, 4)} ${a.slice(4, 8)} ${a.slice(8)}`;
    const content = `const user = { name: "Test", aadhaar: "${a}" };\nconst other = "${spaced}";`;
    const f = await indianPii.detect(repo([{ path: "seed.js", content }]));
    expect(f).toHaveLength(2);
    expect(f[0].evidence).toBe(`XXXX XXXX ${a.slice(8)}`);
    expect(JSON.stringify(f)).not.toContain(a.slice(0, 8));
  });

  it("ignores 12-digit numbers that fail the checksum or have no Aadhaar context", async () => {
    const a = fakeAadhaar();
    const bad = a.slice(0, 11) + ((Number(a[11]) + 1) % 10);
    expect(await indianPii.detect(repo([{ path: "a.js", content: `const aadhaar = "${bad}";\nconst orderId = ${a};` }]))).toEqual([]);
  });

  it("finds a PAN next to its name, masked, and identity data in logs", async () => {
    const pan = "ABCPE" + "1234" + "F";
    const content = `const panNumber = "${pan}";\nconsole.log("kyc", req.body.aadhaar, user.dob);`;
    const f = await indianPii.detect(repo([{ path: "kyc.js", content }]));
    expect(f.map((x) => x.title)).toEqual(["PAN number written in the code", "Identity data written to the logs"]);
    expect(f[0].evidence).toBe("ABXXXXX34F");
  });
});

describe("otp-safety", () => {
  it("flags OTP in the response, in logs, and from Math.random", async () => {
    const code = [
      'app.post("/otp", (req, res) => {',
      "  const otp = Math.floor(100000 + Math.random() * 900000);",
      '  console.log("otp for", req.body.phone, otp);',
      "  res.json({ sent: true, otp });",
      "});",
    ].join("\n");
    const f = await otpSafety.detect(repo([{ path: "auth.js", content: code }]));
    expect(f.map((x) => x.severity)).toEqual(["critical", "high", "medium"]);
  });

  it("is quiet for a safe OTP flow", async () => {
    const code = "const otp = crypto.randomInt(100000, 1000000);\nawait sms.send(phone, otp);\nres.json({ sent: true });";
    expect(await otpSafety.detect(repo([{ path: "auth.js", content: code }]))).toEqual([]);
  });
});

describe("Indian payment and SMS keys in secrets-in-repo", () => {
  it("names the vendor, explains the money risk, and moves the key to an env var", async () => {
    const content = [
      'const PAYTM_MERCHANT_KEY = "kD8#mQ2vX9pL4tRz";',
      'const PHONEPE_SALT_KEY = "099eb0cd-02cf-4e2a-8aca-3e6c6aff0399";',
      'const MSG91_AUTHKEY = "362850AbCdEf1234567890xy";',
      "",
    ].join("\n");
    const ctx = repo([{ path: "pay.js", content }]);
    const f = await secretsInRepo.detect(ctx);
    expect(f.map((x) => x.title)).toEqual(["Paytm merchant key in source", "PhonePe salt key in source", "MSG91 auth key in source"]);
    expect(f[0].explanation).toContain("issue refunds");
    expect(f[2].explanation).toContain("send SMS");
    const patch = await secretsInRepo.fix!(ctx, f);
    const after = patch!.edits.find((e) => e.path === "pay.js");
    expect(after && after.kind === "modify" && after.after).toContain("process.env.PAYTM_MERCHANT_KEY");
  });
});
