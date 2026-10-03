import { useEffect, useRef, useState } from "react";
import api from "../services/api";

const POLL_INTERVAL_MS = 2000;
const MAX_POLL_MS = 2 * 60 * 1000; // never poll forever
// A scan can run for over a minute. One dropped request in that time
// shouldn't end it, so only give up after this many failures in a row.
const MAX_CONSECUTIVE_ERRORS = 3;

/**
 * Polls /api/scan/:id/status every 2 seconds until the scan is COMPLETE or
 * FAILED, and tracks the elapsed time for the UI. Gives up after 2 minutes
 * and reports a timeout.
 */
export default function useScanPolling(scanId) {
  const [status, setStatus] = useState("PENDING");
  const [errorMessage, setErrorMessage] = useState(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [timedOut, setTimedOut] = useState(false);
  const startRef = useRef(Date.now());

  useEffect(() => {
    if (!scanId) return undefined;

    startRef.current = Date.now();
    setStatus("PENDING");
    setErrorMessage(null);
    setElapsedMs(0);
    setTimedOut(false);

    let cancelled = false;
    let pollTimer;
    let clockTimer;
    let errorsInARow = 0;

    const stop = () => {
      clearInterval(pollTimer);
      clearInterval(clockTimer);
    };

    const poll = async () => {
      try {
        const data = await api.get(`/scan/${scanId}/status`);
        if (cancelled) return;
        errorsInARow = 0;
        setStatus(data.status);
        if (data.error_message) setErrorMessage(data.error_message);
        if (data.status === "COMPLETE" || data.status === "FAILED") stop();
      } catch (err) {
        if (cancelled) return;
        errorsInARow += 1;
        // A 404 won't fix itself, so fail on it straight away.
        if (err.code !== "NOT_FOUND" && errorsInARow < MAX_CONSECUTIVE_ERRORS) return;
        setStatus("FAILED");
        setErrorMessage(err.message || "Couldn't reach the server.");
        stop();
      }
    };

    poll();
    pollTimer = setInterval(poll, POLL_INTERVAL_MS);
    clockTimer = setInterval(() => {
      const elapsed = Date.now() - startRef.current;
      setElapsedMs(elapsed);
      if (elapsed > MAX_POLL_MS) {
        setTimedOut(true);
        stop();
      }
    }, 1000);

    return () => {
      cancelled = true;
      stop();
    };
  }, [scanId]);

  return { status, errorMessage, elapsedMs, timedOut };
}
