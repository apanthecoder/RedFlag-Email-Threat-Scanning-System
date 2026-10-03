import { useEffect, useState } from "react";

const GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/** Reveals a word left to right out of random characters, like a display
 * settling on a reading.
 *
 * Used on the verdict label. Under reduced motion the word just appears.
 * Give the element an aria-label with the real text, because the random
 * frames would be nonsense to a screen reader.
 */
export default function useDecode(text, { duration = 650 } = {}) {
  const prefersReduced =
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const [output, setOutput] = useState(prefersReduced ? text : "");

  useEffect(() => {
    if (prefersReduced || !text) {
      setOutput(text);
      return undefined;
    }

    let frame;
    const start = performance.now();
    const tick = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      const settled = Math.floor(progress * text.length);
      let next = text.slice(0, settled);
      for (let i = settled; i < text.length; i += 1) {
        next += text[i] === " " ? " " : GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
      }
      setOutput(next);
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [text, duration, prefersReduced]);

  return output;
}
