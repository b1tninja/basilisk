import { createRoot } from "react-dom/client";
import { useEffect, useRef } from "react";
import { Layout } from "../components/Layout";
import { mountKey } from "../lib/key-mount.js";

function KeyPage() {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    mountKey(el);
  }, []);

  return (
    <Layout active="key">
      <div ref={ref}>
        <p id="error" className="text-error hidden" />
        <p id="loading" className="muted">
          Loading key details…
        </p>
        <div id="content" className="hidden" />
      </div>
    </Layout>
  );
}

createRoot(document.getElementById("app")!).render(<KeyPage />);
