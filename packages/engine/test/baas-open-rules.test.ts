import { describe, expect, it } from "vitest";
import { baasOpenRules } from "../src/checks/baas-open-rules";
import { guardPatch } from "../src/diffGuard";
import type { Finding, Patch, RepoFile } from "../src/types";

const repoOf = (files: RepoFile[]) => ({ name: "t", files });
const detect = (files: RepoFile[]) => baasOpenRules.detect({ repo: repoOf(files) }) as Finding[];
const fix = (files: RepoFile[]) => baasOpenRules.fix!({ repo: repoOf(files) }, []) as Patch | null;

const FIRESTORE = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{id} {
      allow read: if true;
    }
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2026, 12, 1);
    }
    // allow read, write: if true;
  }
}
`;

describe("baas-open-rules", () => {
  it("flags open and test-mode Firestore rules, but not commented ones", () => {
    const f = detect([{ path: "firestore.rules", content: FIRESTORE }]);
    expect(f.map((x) => [x.title, x.severity, x.line])).toEqual([
      ["Rules allow anyone to read", "high", 5],
      ["Rules are still in test mode", "critical", 8],
    ]);
  });

  it("flags an unconditioned allow in storage rules", () => {
    const content = "service firebase.storage {\n  match /b/{bucket}/o {\n    match /{all=**} { allow read, write; }\n  }\n}\n";
    const f = detect([{ path: "storage.rules", content }]);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", line: 3 });
  });

  it("fixes Firebase rules to require sign-in, within the diff guard, and the rescan is clean", () => {
    const files = [{ path: "firestore.rules", content: FIRESTORE }];
    const patch = fix(files)!;
    expect(patch.class).toBe("minimal-edit");
    expect(guardPatch(repoOf(files), patch).ok).toBe(true);
    const after = (patch.edits[0] as { after: string }).after;
    expect(after).toContain("allow read: if request.auth != null;");
    expect(after).toContain("allow read, write: if request.auth != null;");
    expect(after).toContain("// allow read, write: if true;");
    expect(detect([{ path: "firestore.rules", content: after }])).toEqual([]);
  });

  it("flags and fixes open Realtime Database rules", () => {
    const content = '{\n  "rules": {\n    ".read": true,\n    ".write": "true"\n  }\n}\n';
    const files = [{ path: "database.rules.json", content }];
    expect(detect(files).map((x) => x.severity)).toEqual(["high", "critical"]);
    const after = (fix(files)!.edits[0] as { after: string }).after;
    expect(JSON.parse(after).rules).toEqual({ ".read": "auth != null", ".write": "auth != null" });
  });

  it("flags Supabase public tables without RLS and write policies of true, report only", () => {
    const content = [
      "create table public.profiles (id uuid primary key);",
      "create table if not exists notes (id int);",
      "create table private.secrets (id int);",
      "alter table public.profiles enable row level security;",
      'create policy "read all" on profiles for select using (true);',
      'create policy "anyone writes" on profiles for insert with check (true);',
      "-- create table legacy (id int);",
    ].join("\n");
    const files = [{ path: "supabase/migrations/001_init.sql", content }];
    const f = detect(files);
    expect(f.map((x) => [x.title, x.line])).toEqual([
      ["Table notes has no row level security", 2],
      ['Policy "anyone writes" allows any write', 6],
    ]);
    expect(fix(files)).toBeNull();
  });

  it("finds RLS enabled in a later migration, and ignores SQL outside supabase/", () => {
    const files = [
      { path: "supabase/migrations/001.sql", content: "create table orders (id int);" },
      { path: "supabase/migrations/002.sql", content: "alter table orders enable row level security;" },
      { path: "db/schema.sql", content: "create table users (id int);" },
    ];
    expect(detect(files)).toEqual([]);
  });
});
