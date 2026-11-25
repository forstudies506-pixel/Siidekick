/** "sk_live_abcdef123456" -> "sk_l…3456 (20 chars)". Never log a full secret. */
export function redact(secret: string): string {
  if (secret.length <= 8) return `${"*".repeat(secret.length)} (${secret.length} chars)`;
  return `${secret.slice(0, 4)}…${secret.slice(-4)} (${secret.length} chars)`;
}

/** 1-based line number of a character offset. */
export function lineAt(content: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < content.length; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

export const CODE_EXT = /\.(c|m)?(j|t)sx?$/;
/** Prose files: a README that mentions helmet or ufw is not the protection itself. */
export const DOC_EXT = /\.(md|mdx|markdown|txt|rst|adoc)$/i;
