import { createRoot } from "react-dom/client";
import { useEffect, useRef, useState } from "react";
import { Layout } from "../components/Layout";
import { mountQuorum } from "../lib/quorum-mount.js";

function QuorumPage() {
  const [error, setError] = useState("");
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const cleanup = mountQuorum(el, { onError: setError });
    return cleanup;
  }, []);

  return (
    <Layout active="quorum">
      <div className="page-header">
        <h1>Quorum</h1>
        <p className="muted">
          Peer-to-peer encrypted meeting over WebRTC data channels. The creator posts a
          PGP-signed invite proving key possession; joiners mesh only after verifying it. The
          keyserver relays opaque OpenPGP signaling only — it cannot read SDP or chat.
          Data-channel keys use ephemeral ECDH (forward secrecy); room IDs are scoped to this
          hostname.
        </p>
      </div>

      {error ? <p className="text-error">{error}</p> : null}
      <div ref={ref} />
    </Layout>
  );
}

createRoot(document.getElementById("app")!).render(<QuorumPage />);
