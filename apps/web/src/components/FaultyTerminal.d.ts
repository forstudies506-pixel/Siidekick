import type { CSSProperties, JSX } from "react";

/** Types for the React Bits FaultyTerminal (JavaScript + CSS variant), so TypeScript files can import it. */
export interface FaultyTerminalProps {
  scale?: number;
  gridMul?: [number, number];
  digitSize?: number;
  timeScale?: number;
  pause?: boolean;
  scanlineIntensity?: number;
  glitchAmount?: number;
  flickerAmount?: number;
  noiseAmp?: number;
  chromaticAberration?: number;
  dither?: number | boolean;
  curvature?: number;
  tint?: string;
  mouseReact?: boolean;
  mouseStrength?: number;
  pageLoadAnimation?: boolean;
  brightness?: number;
  glyphs?: "blocks" | "dots" | "characters";
  glow?: number;
  persistence?: number;
  scramble?: number;
  mouseGlow?: number;
  vignette?: number;
  clickEffect?: "glitch" | "degauss" | "none";
  variation?: number;
  lightMode?: boolean;
  dpr?: number;
  /** Cap the redraw rate (0 = every display frame). */
  maxFps?: number;
  className?: string;
  style?: CSSProperties;
}

export default function FaultyTerminal(props: FaultyTerminalProps): JSX.Element;
