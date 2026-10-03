import { useEffect, useRef, useState } from "react";

/** Reports when an element first scrolls into view, then stops watching.
 *
 * It only fires once, because content that animates again every time you
 * scroll past gets distracting. With reduced motion turned on it reports
 * visible straight away, so nothing waits on an animation that won't run.
 */
export default function useInView({ threshold = 0.25, rootMargin = "0px 0px -10% 0px" } = {}) {
  const ref = useRef(null);
  const prefersReduced =
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const [inView, setInView] = useState(prefersReduced);

  useEffect(() => {
    if (prefersReduced) return undefined;
    const node = ref.current;
    if (!node || typeof IntersectionObserver === "undefined") {
      setInView(true);
      return undefined;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInView(true);
          observer.disconnect();
        }
      },
      { threshold, rootMargin }
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [threshold, rootMargin, prefersReduced]);

  return [ref, inView];
}
