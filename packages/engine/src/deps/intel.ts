/**
 * Exploit intelligence for prioritising dependency findings, beyond CVSS severity:
 * - CISA Known Exploited Vulnerabilities (KEV): CVEs seen exploited in the wild.
 * - FIRST EPSS: the modelled probability that a CVE is exploited in the next 30 days.
 * Both are free public feeds. Failures never fail the scan: findings then just lack this context.
 */

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss?cve=";
const TIMEOUT_MS = 8000;
const KEV_TTL_MS = 6 * 60 * 60 * 1000;
const EPSS_BATCH = 100;

export interface ExploitIntel {
  /** CVE → date CISA added it to KEV. */
  kev: Map<string, string>;
  /** CVE → { probability 0..1, percentile 0..1 }. */
  epss: Map<string, { epss: number; percentile: number }>;
  /** Which feeds answered; shown so "not in KEV" is never confused with "KEV not checked". */
  sources: { kev: boolean; epss: boolean };
}

let kevCache: { at: number; map: Map<string, string> } | null = null;

async function fetchKev(fetchFn: typeof fetch, now: number): Promise<Map<string, string> | null> {
  if (kevCache && now - kevCache.at < KEV_TTL_MS) return kevCache.map;
  try {
    const res = await fetchFn(KEV_URL, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!res.ok) return null;
    const body = (await res.json()) as { vulnerabilities?: { cveID?: string; dateAdded?: string }[] };
    if (!Array.isArray(body.vulnerabilities)) return null;
    const map = new Map<string, string>();
    for (const v of body.vulnerabilities) if (v.cveID) map.set(v.cveID, v.dateAdded ?? "");
    kevCache = { at: now, map };
    return map;
  } catch {
    return null;
  }
}

async function fetchEpss(fetchFn: typeof fetch, cves: string[]): Promise<ExploitIntel["epss"] | null> {
  const out: ExploitIntel["epss"] = new Map();
  try {
    for (let i = 0; i < cves.length; i += EPSS_BATCH) {
      const res = await fetchFn(EPSS_URL + cves.slice(i, i + EPSS_BATCH).join(","), { signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (!res.ok) return null;
      const body = (await res.json()) as { data?: { cve?: string; epss?: string; percentile?: string }[] };
      for (const d of body.data ?? []) if (d.cve) out.set(d.cve, { epss: Number(d.epss ?? 0), percentile: Number(d.percentile ?? 0) });
    }
    return out;
  } catch {
    return null;
  }
}

export async function exploitIntel(fetchFn: typeof fetch, cves: string[], now = Date.now()): Promise<ExploitIntel> {
  const unique = [...new Set(cves.filter((c) => /^CVE-\d{4}-\d+$/.test(c)))];
  if (unique.length === 0) return { kev: new Map(), epss: new Map(), sources: { kev: false, epss: false } };
  const [kev, epss] = await Promise.all([fetchKev(fetchFn, now), fetchEpss(fetchFn, unique)]);
  return { kev: kev ?? new Map(), epss: epss ?? new Map(), sources: { kev: kev !== null, epss: epss !== null } };
}

/** For tests: forget the cached KEV catalog. */
export function resetIntelCache(): void {
  kevCache = null;
}
