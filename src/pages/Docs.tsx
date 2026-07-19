import { Link } from 'react-router-dom';
import { Shield, ArrowLeft, Globe, Key, Play, Clock, Lock, Lightbulb, AlertTriangle, Keyboard, RefreshCw, Download, Trash2, Eye, EyeOff } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';

const Code: React.FC<{ children: string }> = ({ children }) => (
  <code className="text-xs bg-code-bg p-1.5 rounded border border-code-border font-mono break-all code-block">{children}</code>
);

const Section: React.FC<{ id: string; icon: React.ReactNode; title: string; children: React.ReactNode }> = ({ id, icon, title, children }) => (
  <section id={id} className="scroll-mt-24">
    <h2 className="flex items-center gap-2 text-xl font-semibold mb-3 pb-2 border-b border-border">
      <span className="text-primary">{icon}</span>
      {title}
    </h2>
    <div className="space-y-3 text-sm leading-relaxed text-muted-foreground [&_strong]:text-foreground [&_a]:text-primary [&_a:hover]:text-primary-glow">{children}</div>
  </section>
);

const Step: React.FC<{ n: number; title: string; children: React.ReactNode }> = ({ n, title, children }) => (
  <div className="flex gap-3">
    <div className="flex-shrink-0 w-7 h-7 rounded-full bg-primary/20 border border-primary text-primary text-xs font-semibold flex items-center justify-center">
      {n}
    </div>
    <div className="flex-1 space-y-2 pt-0.5">
      <p className="font-medium text-foreground">{title}</p>
      <div className="text-sm text-muted-foreground space-y-2">{children}</div>
    </div>
  </div>
);

const Docs = () => (
  <div className="min-h-screen bg-background text-foreground p-4">
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div className="text-center py-8 relative">
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="w-64 h-64 bg-primary/5 rounded-full blur-3xl" />
        </div>
        <div className="relative inline-flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary to-primary-glow flex items-center justify-center shadow-glow-primary">
            <Shield className="w-6 h-6 text-primary-foreground" />
          </div>
          <h1 className="text-3xl font-mono font-bold tracking-tight">
            <span className="text-foreground">oidc</span>
            <span className="text-primary">playpen</span>
          </h1>
        </div>
        <p className="text-sm text-muted-foreground relative tracking-wide uppercase">
          Documentation &amp; Usage Guide
        </p>
      </div>

      <div className="flex justify-between items-center gap-2 flex-wrap">
        <Link to="/" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="h-4 w-4" />
          Back to the tool
        </Link>
        <nav className="text-xs text-muted-foreground flex flex-wrap gap-x-3 gap-y-1">
          <a href="#quick-start" className="hover:text-primary">Quick start</a>
          <a href="#setup" className="hover:text-primary">Setup</a>
          <a href="#flows" className="hover:text-primary">Flows</a>
          <a href="#tabs" className="hover:text-primary">Tabs</a>
          <a href="#secrets" className="hover:text-primary">Secrets</a>
          <a href="#shortcuts" className="hover:text-primary">Shortcuts</a>
          <a href="#faq" className="hover:text-primary">FAQ</a>
        </nav>
      </div>

      {/* Intro */}
      <div className="space-y-3 text-sm text-muted-foreground">
        <p>
          <strong className="text-foreground">OIDC Playpen</strong> is a browser-based tool for testing OpenID Connect providers.
          Point it at a provider, fill in your client details, run a flow, and inspect every request, response, and token
          in detail — including decoded JWTs and redacted logs. It runs entirely client-side; no secrets leave your browser
          except to the provider itself.
        </p>
      </div>

      {/* Quick start */}
      <Section id="quick-start" icon={<Play className="h-5 w-5" />} title="Quick start (30 seconds)">
        <Step n={1} title="Open the Provider Setup tab">
          Enter your provider's base URL (e.g. <Code>https://accounts.google.com</Code>) and hit <strong>Fetch Config</strong>.
          The tool pulls <Code>.well-known/openid-configuration</Code> and fills in the endpoints.
        </Step>
        <Step n={2} title="Open the Client Config tab">
          Type your <strong>Client ID</strong> and (if your client has one) <strong>Client Secret</strong>. Pick a flow type
          (Authorization Code + PKCE is the recommended default). Adjust scopes if needed.
        </Step>
        <Step n={3} title="Click Begin Flow">
          A popup opens to the provider's login page. After you authenticate, the popup closes and the tool exchanges the
          code for tokens.
        </Step>
        <Step n={4} title="Inspect the Tokens tab">
          Decode JWTs, copy values, fetch the UserInfo endpoint, and refresh tokens if your provider issued a refresh token.
        </Step>
        <Step n={5} title="Dig into Request Logs">
          Every HTTP request and the redirect callback are logged with headers, payload, response status, duration, and
          redacted secrets.
        </Step>
      </Section>

      {/* Setup */}
      <Section id="setup" icon={<Globe className="h-5 w-5" />} title="Provider setup &amp; manual config">
        <p>
          The tool uses OIDC Discovery by default — it fetches the provider's metadata from
          <Code>{'<baseUrl>/.well-known/openid-configuration'}</Code>. If that endpoint is unreachable (CORS, network,
          non-standard path), the toast reports the real error instead of guessing "CORS".
        </p>
        <p>
          When discovery can't be used, toggle <strong>Use Manual Configuration</strong> and fill in the endpoints by hand:
          issuer, authorization, token, userinfo, and JWKS URI. Manual config bypasses discovery entirely — the tool uses
          whatever you enter.
        </p>
        <Alert>
          <Lightbulb className="h-4 w-4" />
          <AlertDescription>
            Your config (including client secret) and request logs persist to <Code>localStorage</Code> under
            <Code>oidc-playpen:state:v1</Code>. Refreshing the page restores everything. Clear your browser storage to wipe it.
          </AlertDescription>
        </Alert>
      </Section>

      {/* Flows */}
      <Section id="flows" icon={<Key className="h-5 w-5" />} title="Supported flows">
        <ul className="list-disc pl-5 space-y-2">
          <li>
            <strong>Authorization Code + PKCE (Recommended)</strong> — runs a full redirect flow with PKCE
            (<Code>S256</Code>). The code verifier is stored in <Code>sessionStorage</Code> and used during the token
            exchange. Best for SPA and mobile clients.
          </li>
          <li>
            <strong>Implicit Flow (Deprecated)</strong> — included for testing legacy providers. The UI warns that
            RFC 9700 deprecates this flow. Tokens come back in the redirect URL fragment.
          </li>
          <li>
            <strong>Hybrid Flow</strong> — request type <Code>code id_token token</Code>. Combines an auth code with
            tokens returned in the front-channel.
          </li>
          <li>
            <strong>Client Credentials (no user redirect)</strong> — for machine-to-machine clients. The tool POSTs
            directly to the token endpoint with <Code>grant_type=client_credentials</Code>; no popup or redirect is
            used. If a client secret is set, it's sent as <Code>Authorization: Basic</Code>; otherwise
            <Code>client_id</Code> goes in the body.
          </li>
        </ul>
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Authorization codes are single-use per RFC 6749 §4.1.2. The <strong>Re-exchange Code</strong> button only
            appears when the first exchange failed — otherwise it would always fail.
          </AlertDescription>
        </Alert>
      </Section>

      {/* Tabs */}
      <Section id="tabs" icon={<Clock className="h-5 w-5" />} title="The four tabs">
        <p><strong className="text-foreground">Provider Setup</strong> — discovery URL + fetch, or manual endpoint entry. Shows the loaded discovery document, supported scopes, and a switch to bypass discovery.</p>
        <p><strong className="text-foreground">Client Config</strong> — client ID/secret, flow type, redirect URI, scopes, generated auth URL, and the <strong>Begin Flow</strong> button.</p>
        <p><strong className="text-foreground">Tokens</strong> — every field from the token response. Secret token fields (<Code>access_token</Code>, <Code>id_token</Code>, <Code>refresh_token</Code>) are <strong>masked by default</strong>; click the eye icon to reveal. JWTs are auto-decoded to header/payload/signature. Use <strong>Fetch UserInfo</strong>, <strong>Refresh</strong>, or <strong>Re-exchange Code</strong> from here.</p>
        <p><strong className="text-foreground">Request Logs</strong> — every request (discovery GET, token POST, userinfo GET, redirect callback) with method, URL, status, duration, and collapsible sections for URL, headers, payload, response headers, and response body. Use <strong>Clear</strong> to wipe or <strong>Export</strong> to download a JSON dump.</p>
      </Section>

      {/* Secrets */}
      <Section id="secrets" icon={<Lock className="h-5 w-5" />} title="How secrets are handled">
        <p>
          OIDC Playpen treats credentials defensively — a test tool shouldn't accidentally leak your client secret.
        </p>
        <ul className="list-disc pl-5 space-y-2">
          <li><strong>Client secret</strong> is hidden behind a password input with a reveal toggle (<Eye className="inline h-3 w-3" /> / <EyeOff className="inline h-3 w-3" />).</li>
          <li><strong>Tokens</strong> are masked — only the first/last few characters show until you click reveal.</li>
          <li><strong>Authorization headers</strong> in logs (both request and response) display as <Code>[REDACTED]</Code>. The original values stay in memory for re-sending but never render.</li>
          <li><strong>Export</strong> redacts secrets by default. Tick <em>Include secrets</em> only if you need a full debug bundle — the filename gets a <Code>-WITH-SECRETS</Code> suffix as a visual warning.</li>
          <li><strong>localStorage persistence</strong> stores your client secret so you don't lose it on refresh. To opt out, clear site data or use your browser's private mode.</li>
        </ul>
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            The tool sends your secret to the token endpoint as required by the OIDC spec — that's its job. It does not
            send anything to any other host and contains no analytics.
          </AlertDescription>
        </Alert>
      </Section>

      {/* Shortcuts */}
      <Section id="shortcuts" icon={<Keyboard className="h-5 w-5" />} title="Keyboard shortcuts">
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>Enter</strong> in the Base URL field → fetch discovery</li>
          <li><strong>Ctrl/Cmd + Enter</strong> (outside inputs) → start the flow / request token</li>
          <li><strong>Tab</strong> through inputs as normal; icon-only buttons have <Code>aria-label</Code>s for screen readers</li>
        </ul>
      </Section>

      {/* FAQ */}
      <Section id="faq" icon={<Lightbulb className="h-5 w-5" />} title="FAQ">
        <p><strong className="text-foreground">The popup doesn't open.</strong> Your browser blocked it. Allow popups for this site — the tool detects the block and warns you with a toast. You can also click <strong>Generate URL</strong> and open the auth URL manually in the same tab.</p>
        <p><strong className="text-foreground">Discovery fails with a CORS error.</strong> Some providers don't allow cross-origin discovery fetches. Toggle <strong>Use Manual Configuration</strong> and fill in the endpoints by hand. The tool no longer assumes every failure is CORS — it shows the real HTTP status or network error.</p>
        <p><strong className="text-foreground">My token expired.</strong> If your provider issued a <Code>refresh_token</Code>, the Tokens tab shows a <RefreshCw className="inline h-3 w-3" /> <strong>Refresh</strong> button. Otherwise, run the flow again.</p>
        <p><strong className="text-foreground">I want a fresh start.</strong> The Logs tab has a <Trash2 className="inline h-3 w-3" /> <strong>Clear</strong> button for logs. To wipe everything (config, secret, logs), clear <Code>localStorage</Code> for the site — the key is <Code>oidc-playpen:state:v1</Code>.</p>
        <p><strong className="text-foreground">Can I export a session?</strong> Yes — use <Download className="inline h-3 w-3" /> <strong>Export</strong> in the Logs tab. You'll get a JSON bundle of config, discovery, tokens, userinfo, and logs. Pick whether to include secrets at export time.</p>
        <p><strong className="text-foreground">The redirect URI isn't working.</strong> The default is <Code>{'<origin>/redirect.html'}</Code>. The file <Code>public/redirect.html</Code> parses the callback, validates <Code>state</Code> against <Code>sessionStorage</Code>, and posts the result back to the opener. Make sure your provider's registered redirect URI matches exactly (scheme, host, port, path).</p>
      </Section>

      {/* Footer */}
      <div className="border-t border-border pt-6 text-center text-xs text-muted-foreground space-y-1">
        <p>
          OIDC Playpen — a client-side testing tool. No server, no analytics, no telemetry.
        </p>
        <p>
          <Link to="/" className="text-primary hover:text-primary-glow">← Back to the tool</Link>
        </p>
      </div>
    </div>
  </div>
);

export default Docs;
