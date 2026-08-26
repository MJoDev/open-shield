import { useEffect, useState } from "react";
import { api, ApiError } from "./api";
import { Events } from "./views/Events";
import { Forensics } from "./views/Forensics";
import { Live } from "./views/Live";
import { Rules } from "./views/Rules";

type Tab = "live" | "events" | "rules" | "forensics";

const TABS: { id: Tab; label: string }[] = [
  { id: "live", label: "En vivo" },
  { id: "events", label: "Auditoría" },
  { id: "rules", label: "Reglas" },
  { id: "forensics", label: "Forense" },
];

export function App() {
  const [user, setUser] = useState<string | null>(null);
  const [checking, setChecking] = useState(true);
  const [tab, setTab] = useState<Tab>("live");

  useEffect(() => {
    api
      .session()
      .then((s) => setUser(s.user))
      .catch(() => setUser(null))
      .finally(() => setChecking(false));
  }, []);

  if (checking) {
    return <div className="boot">Cargando…</div>;
  }

  if (!user) {
    return <Login onSignedIn={setUser} />;
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <ShieldMark />
          <span>open-shield</span>
        </div>

        <nav className="tabs">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              className={tab === t.id ? "tab tab-active" : "tab"}
              onClick={() => setTab(t.id)}
              aria-current={tab === t.id ? "page" : undefined}
            >
              {t.label}
            </button>
          ))}
        </nav>

        <div className="session">
          <span className="muted">{user}</span>
          <button
            type="button"
            className="link-button"
            onClick={async () => {
              await api.logout().catch(() => undefined);
              setUser(null);
            }}
          >
            Salir
          </button>
        </div>
      </header>

      <main>
        {tab === "live" && <Live />}
        {tab === "events" && <Events />}
        {tab === "rules" && <Rules />}
        {tab === "forensics" && <Forensics />}
      </main>
    </div>
  );
}

function Login({ onSignedIn }: { onSignedIn: (user: string) => void }) {
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const session = await api.login(user, password);
      onSignedIn(session.user);
    } catch (err) {
      // The API answers the same way for a wrong user and a wrong password, so
      // there is nothing here to distinguish between them either.
      setError(
        err instanceof ApiError && err.status === 429
          ? err.message
          : "Usuario o contraseña incorrectos.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit}>
        <div className="brand brand-large">
          <ShieldMark />
          <span>open-shield</span>
        </div>
        <p className="muted">Panel de administración</p>

        <label>
          Usuario
          <input
            type="text"
            autoComplete="username"
            required
            value={user}
            onChange={(e) => setUser(e.target.value)}
          />
        </label>

        <label>
          Contraseña
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>

        {error && <p className="error-banner">{error}</p>}

        <button type="submit" disabled={busy}>
          {busy ? "Entrando…" : "Entrar"}
        </button>
      </form>
    </div>
  );
}

function ShieldMark() {
  return (
    <svg viewBox="0 0 24 24" className="shield" aria-hidden="true">
      <path
        d="M12 2.5 4.5 5.5v6c0 4.6 3.1 8.7 7.5 10 4.4-1.3 7.5-5.4 7.5-10v-6L12 2.5Z"
        fill="none"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path
        d="m8.6 12.1 2.4 2.4 4.4-4.6"
        fill="none"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
