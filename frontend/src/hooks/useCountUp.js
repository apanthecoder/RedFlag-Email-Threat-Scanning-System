import { useEffect, useState } from "react";

/** Counts from zero up to a target once `active` becomes true.
 *
 * Used for the statistic on the upload page and the score on the report.
 * Under reduced motion it returns the final value straight away, so it
 * never gets stuck at zero.
 */
export default function useCountUp(target, active, { duration = 1100, decimals = 0 } = {}) {
  const prefersReduced =
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const [value, setValue] = useState(prefersReduced ? target : 0);

  useEffect(() => {
    if (!active || prefersReduced) {
      if (prefersReduced) setValue(target);
      return undefined;
    }

    let frame;
    const start = performance.now();
    const tick = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      // Ease out: fast at first, slowing down near the end.
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Number((target * eased).toFixed(decimals)));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, active, duration, decimals, prefersReduced]);

  return value.toFixed(decimals);
}
