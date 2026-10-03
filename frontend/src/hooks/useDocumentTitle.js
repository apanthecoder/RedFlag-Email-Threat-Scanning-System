import { useEffect } from "react";

/** Sets the browser tab title for the current page and puts the old one
 * back on unmount. */
export default function useDocumentTitle(title) {
  useEffect(() => {
    const previous = document.title;
    document.title = title ? `${title} · RedFlag` : "RedFlag";
    return () => {
      document.title = previous;
    };
  }, [title]);
}
