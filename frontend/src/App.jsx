import { useEffect, useState } from "react";
import { Link, NavLink, Route, Routes, useLocation } from "react-router-dom";
import UploadPage from "./pages/UploadPage.jsx";
import ReportPage from "./pages/ReportPage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import AdminDashboardPage from "./pages/AdminDashboardPage.jsx";
import Logo from "./components/Logo.jsx";

function navLinkClass({ isActive }) {
  return [
    "press rounded-full px-3.5 py-1.5 text-small font-medium",
    isActive ? "bg-paper/[0.08] text-paper" : "text-muted hover:text-paper",
  ].join(" ");
}

/** True once the page has scrolled away from the top. */
function useScrolled() {
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 4);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  return scrolled;
}

export default function App() {
  const location = useLocation();
  const scrolled = useScrolled();

  return (
    <div className="min-h-[100dvh] bg-ink">
      {/* A translucent bar that content scrolls under. Its bottom edge only
          appears once something is actually underneath it. */}
      <header
        className="material sticky top-0 z-30 transition-[box-shadow] duration-200"
        style={{
          paddingTop: "env(safe-area-inset-top)",
          paddingLeft: "env(safe-area-inset-left)",
          paddingRight: "env(safe-area-inset-right)",
          boxShadow: scrolled ? "0 1px 0 var(--material-edge)" : "0 1px 0 transparent",
        }}
      >
        <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-5 sm:px-6">
          <Link to="/" className="group -mx-1.5 rounded-lg px-1.5 py-1" aria-label="RedFlag home">
            <Logo />
          </Link>
          <nav className="flex items-center gap-1">
            <NavLink to="/history" className={navLinkClass}>
              History
            </NavLink>
            <NavLink to="/admin" className={navLinkClass}>
              Admin
            </NavLink>
          </nav>
        </div>
      </header>

      {/* Keyed on the path so each page fades in when you navigate to it. */}
      <div key={location.pathname} className="motion-safe:animate-fade">
        <Routes>
          <Route path="/" element={<UploadPage />} />
          <Route path="/scan/:scanId" element={<ReportPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/admin" element={<AdminDashboardPage />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </div>
    </div>
  );
}

function NotFound() {
  return (
    <main className="mx-auto max-w-5xl px-5 py-24 sm:px-6">
      <h1 className="text-display font-semibold text-paper">This page does not exist</h1>
      <p className="mt-3 max-w-prose text-lead text-muted">
        Check the address, or start a new scan from the home page.
      </p>
      <Link to="/" className="btn-primary mt-8">
        Scan an email
      </Link>
    </main>
  );
}
