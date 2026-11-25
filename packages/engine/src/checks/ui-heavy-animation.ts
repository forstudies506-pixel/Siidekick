import type { Check, Finding } from "../types.js";
import { lineAt } from "../util.js";

const ANIMATED_PROPS = /\b(left|top|right|bottom|width|height|margin)\b/;
const KEYFRAMES = /@keyframes\s+(\S+)\s*\{([\s\S]*?)\}/g;
const INLINE_SCRIPT = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
const SCRIPT_SRC = /<script\b[^>]*\bsrc\s*=/i;

export const uiHeavyAnimation: Check = {
  id: "ui-heavy-animation",
  group: "E-states",
  title: "Heavy UI animation",
  severity: "low",
  mode: "report",

  detect({ repo }): Finding[] {
    const findings: Finding[] = [];
    for (const f of repo.files) {
      if (!f.path.endsWith(".css") && !f.path.endsWith(".html")) continue;
      for (const m of f.content.matchAll(KEYFRAMES)) {
        if (ANIMATED_PROPS.test(m[2])) {
          findings.push({
            checkId: "ui-heavy-animation",
            title: `Keyframes animates layout property: ${m[1]}`,
            severity: "low",
            file: f.path,
            line: lineAt(f.content, m.index),
            explanation: "Animating left/top/width/height/margin forces layout on every frame. Prefer transform/opacity, which composite cheaply.",
          });
        }
      }
      for (const m of f.content.matchAll(INLINE_SCRIPT)) {
        if (SCRIPT_SRC.test(m[0])) continue;
        const lines = m[1].split("\n").length;
        if (lines > 200) {
          findings.push({
            checkId: "ui-heavy-animation",
            title: "Inline script over 200 lines",
            severity: "low",
            file: f.path,
            line: lineAt(f.content, m.index),
            explanation: "Large inline scripts block parsing. Move to an external file with defer or lazy-load it.",
          });
        }
      }
    }
    return findings;
  },
};
