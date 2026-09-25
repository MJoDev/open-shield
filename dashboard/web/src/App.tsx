import { useEffect, useState } from "react";
import { api, ApiError, setUnauthorizedHandler } from "./api";
import { ErrorBanner } from "./components/Feedback";
import { describeError, type Problem } from "./errors";
import { useDelayedFlag } from "./hooks";
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
  // Views stay mounted once visited. Unmounting on every tab switch threw
  // away the live feed's buffer and the last page of every view, so coming
  // back meant a skeleton and an empty feed for data that was just there.
  const [visited, setVisited] = useState<ReadonlySet<Tab>>(new Set(["live"]));
  const [expired, setExpired] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const showBoot = useDelayedFlag(checking);

  useEffect(() => {
    api
      .session()
      .then((s) => setUser(s.user))
      .catch(() => setUser(null))
      .finally(() => setChecking(false));
  }, []);

  // Any signed-in call that answers 401 means the session is gone. The
  // screens would otherwise each show a raw "no session" error; the only
  // useful answer is the sign-in form, saying why it is back.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setExpired(true);
      setUser(null);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  if (checking) {
    // Under the indicator delay the check is invisible; past it, the brand
    // mark says what is loading rather than a bare "Cargando…".
    return (
      <div className="boot" aria-busy="true">
        {showBoot && (
          <div className="boot-mark" role="status">
            <ShieldMark />
            <span>Comprobando la sesión…</span>
          </div>
        )}
      </div>
    );
  }

  if (!user) {
    return (
      <Login
        expired={expired}
        onSignedIn={(name) => {
          setExpired(false);
          setUser(name);
        }}
      />
    );
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
              onClick={() => {
                setTab(t.id);
                setVisited((current) => new Set(current).add(t.id));
              }}
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
            disabled={leaving}
            aria-busy={leaving}
            onClick={async () => {
              setLeaving(true);
              await api.logout().catch(() => undefined);
              setLeaving(false);
              setUser(null);
            }}
          >
            {leaving ? "Saliendo…" : "Salir"}
          </button>
        </div>
      </header>

      <main>
        {visited.has("live") && (
          <div hidden={tab !== "live"}>
            <Live />
          </div>
        )}
        {visited.has("events") && (
          <div hidden={tab !== "events"}>
            <Events />
          </div>
        )}
        {visited.has("rules") && (
          <div hidden={tab !== "rules"}>
            <Rules />
          </div>
        )}
        {visited.has("forensics") && (
          <div hidden={tab !== "forensics"}>
            <Forensics />
          </div>
        )}
      </main>
    </div>
  );
}

function Login({
  expired,
  onSignedIn,
}: {
  expired: boolean;
  onSignedIn: (user: string) => void;
}) {
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<Problem | null>(null);
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
      // there is nothing here to distinguish between them either. Only a 401
      // means that, though: a server that is down or timing out must not be
      // reported as a mistyped password.
      if (err instanceof ApiError && err.status === 401) {
        setError({ title: "Usuario o contraseña incorrectos." });
      } else if (err instanceof ApiError && err.status === 429) {
        setError({
          title:
            "Demasiados intentos fallidos. Espera unos minutos antes de volver a probar.",
          detail: `${err.message} (HTTP 429)`,
        });
      } else {
        setError(describeError(err, "No se pudo iniciar sesión."));
      }
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

        {expired && !error && (
          <p className="note" role="status">
            Tu sesión expiró. Vuelve a entrar para continuar.
          </p>
        )}

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

        {error && <ErrorBanner problem={error} />}

        <button type="submit" disabled={busy} aria-busy={busy}>
          {busy ? (
            <>
              <span className="spinner" aria-hidden="true" />
              Entrando…
            </>
          ) : (
            "Entrar"
          )}
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
