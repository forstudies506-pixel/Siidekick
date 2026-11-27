import { useEffect } from "react";

/**
 * The light the glass refracts. A fixed field of two soft lights and a fine grid sits behind everything; the
 * `.lens` surfaces bend it through an SVG displacement filter (Chromium supports `backdrop-filter: url()`;
 * other browsers get frosted glass). The pointer moves a specular highlight on whichever lens it is over.
 */

export function LightField() {
  useEffect(() => {
    const ua = navigator as Navigator & { userAgentData?: { brands?: { brand: string }[] } };
    const chromium = ua.userAgentData?.brands?.some((b) => /Chromium|Google Chrome|Microsoft Edge/.test(b.brand)) ?? false;
    const root = document.documentElement;
    if (chromium) root.classList.add("has-refraction");
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (still) return () => root.classList.remove("has-refraction");
    let frame = 0;
    let last: HTMLElement | null = null;
    const move = (e: PointerEvent) => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        const lens = (e.target as Element | null)?.closest?.(".lens, .site-header, .dashboard-header, .scan-strip, .repo-form, .hero-form, .pane, .side-card, .india-lens, .findings-rail, .finding-list, .fix-list, .fix-detail, .manual-list, .still-failing, .ship-card, .aws-panel, .proof-panel, .viz-card, .verify-scores > div, .state-box, .empty-state, .step-cta, .check-col, .flow li, .catch, .facts") as HTMLElement | null;
        if (last && last !== lens) last.style.removeProperty("--lit");
        if (!lens) return;
        const r = lens.getBoundingClientRect();
        lens.style.setProperty("--mx", `${((e.clientX - r.left) / r.width) * 100}%`);
        lens.style.setProperty("--my", `${((e.clientY - r.top) / r.height) * 100}%`);
        lens.style.setProperty("--lit", "1");
        last = lens;
      });
    };
    document.addEventListener("pointermove", move, { passive: true });
    return () => {
      document.removeEventListener("pointermove", move);
      cancelAnimationFrame(frame);
      root.classList.remove("has-refraction");
    };
  }, []);

  return (
    <>
      <div className="light-field" aria-hidden="true">
        <span className="lf-light lf-saffron" />
        <span className="lf-light lf-indus" />
        <span className="lf-grid" />
      </div>
      <svg className="lf-defs" aria-hidden="true" focusable="false" width="0" height="0">
        {/* Smooth, low-frequency displacement: bends what is behind the glass like thick liquid glass.
            (Chromium applies url() filters in backdrop-filter; image-based maps do not render there.) */}
        <filter id="siidekick-lens" x="-5%" y="-5%" width="110%" height="110%" colorInterpolationFilters="sRGB">
          <feTurbulence type="fractalNoise" baseFrequency="0.0035 0.008" numOctaves="1" seed="11" result="flow" />
          <feGaussianBlur in="flow" stdDeviation="6" result="soft" />
          <feDisplacementMap in="SourceGraphic" in2="soft" scale="46" xChannelSelector="R" yChannelSelector="G" />
        </filter>
      </svg>
    </>
  );
}
