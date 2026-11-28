import { useEffect } from "react";
import FaultyTerminal from "./FaultyTerminal";

/**
 * The light the glass refracts. A fixed field of saffron-to-indus LEDs (FaultyTerminal) sits behind everything; the
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
        {/* The LEDs are the light source: a dim, slow terminal field whose lit cells take the saffron-to-indus
            gradient (multiplied onto white LEDs, so dark cells stay dark). The glass bends this light. */}
        <div className="lf-terminal">
          <FaultyTerminal
            tint="#ffffff"
            scale={2.3}
            gridMul={[2, 1]}
            digitSize={1.3}
            timeScale={0.12}
            brightness={0.95}
            glow={0.3}
            scanlineIntensity={0.12}
            glitchAmount={0.4}
            flickerAmount={0.25}
            noiseAmp={0.9}
            curvature={0}
            mouseReact
            mouseStrength={0.12}
            mouseGlow={0.35}
            persistence={0.6}
            vignette={0.6}
            clickEffect="none"
            pageLoadAnimation
            dpr={1}
          />
        </div>
      </div>
      <svg className="lf-defs" aria-hidden="true" focusable="false" width="0" height="0">
        {/* Liquid glass (Chromium applies url() filters in backdrop-filter; image-based maps do not render there).
            The displacement map is built from the glass's own shape: SourceAlpha blurred gives 1 inside and falls
            off at the rim, and its slope bends light strongly at the edges like a thick lens while the middle
            stays clear. A faint low-frequency flow adds the liquid wobble. Red, green and blue are displaced by
            slightly different amounts, so edges pick up a subtle prism fringe. */}
        <filter id="siidekick-lens" x="0" y="0" width="100%" height="100%" colorInterpolationFilters="sRGB">
          <feGaussianBlur in="SourceAlpha" stdDeviation="14" result="rimA" />
          <feColorMatrix in="rimA" type="matrix" values="0 0 0 1 0  0 0 0 1 0  0 0 0 1 0  0 0 0 0 1" result="rim" />
          <feOffset in="rim" dx="8" dy="0" result="rimX" />
          <feOffset in="rim" dx="0" dy="8" result="rimY" />
          <feComposite in="rim" in2="rimX" operator="arithmetic" k1="0" k2="3" k3="-3" k4="0.5" result="slopeX" />
          <feComposite in="rim" in2="rimY" operator="arithmetic" k1="0" k2="3" k3="-3" k4="0.5" result="slopeY" />
          <feColorMatrix in="slopeX" type="matrix" values="1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 0 1" result="mapX" />
          <feColorMatrix in="slopeY" type="matrix" values="0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 0 1" result="mapY" />
          <feComposite in="mapX" in2="mapY" operator="arithmetic" k1="0" k2="1" k3="1" k4="0" result="lensMap" />
          <feTurbulence type="fractalNoise" baseFrequency="0.0035 0.008" numOctaves="1" seed="11" result="flow" />
          <feGaussianBlur in="flow" stdDeviation="6" result="soft" />
          <feComposite in="lensMap" in2="soft" operator="arithmetic" k1="0" k2="1" k3="0.3" k4="-0.15" result="map" />
          <feDisplacementMap in="SourceGraphic" in2="map" scale="56" xChannelSelector="R" yChannelSelector="G" result="dR" />
          <feDisplacementMap in="SourceGraphic" in2="map" scale="50" xChannelSelector="R" yChannelSelector="G" result="dG" />
          <feDisplacementMap in="SourceGraphic" in2="map" scale="44" xChannelSelector="R" yChannelSelector="G" result="dB" />
          <feColorMatrix in="dR" type="matrix" values="1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0" result="cR" />
          <feColorMatrix in="dG" type="matrix" values="0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 1 0" result="cG" />
          <feColorMatrix in="dB" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 1 0 0  0 0 0 1 0" result="cB" />
          <feBlend in="cR" in2="cG" mode="screen" result="rg" />
          <feBlend in="rg" in2="cB" mode="screen" />
        </filter>
      </svg>
    </>
  );
}
