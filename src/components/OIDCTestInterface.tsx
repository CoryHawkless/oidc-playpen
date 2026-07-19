import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import SetupTab from '@/components/oidc/SetupTab';
import ConfigTab from '@/components/oidc/ConfigTab';
import TokensTab from '@/components/oidc/TokensTab';
import LogsTab from '@/components/oidc/LogsTab';
import FlowStepper from '@/components/oidc/FlowStepper';
import ExportDialog from '@/components/oidc/ExportDialog';
import { Shield, BookOpen } from 'lucide-react';
import { copyText, redactHeaders } from '@/lib/oidc-utils';
import type { DiscoveryDocument, OIDCConfig, RequestLog, TokenResponse, FlowStep, TabValue } from '@/components/oidc/types';
import { MAX_LOGS, STORAGE_KEY } from '@/components/oidc/types';

interface PersistedState {
  config: OIDCConfig;
  requestLogs: RequestLog[];
}

function loadPersistedState(): PersistedState | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as PersistedState;
    if (Array.isArray(parsed.requestLogs)) {
      parsed.requestLogs = parsed.requestLogs.map((l) => ({ ...l, timestamp: new Date(l.timestamp) }));
    }
    return parsed;
  } catch {
    return null;
  }
}

function savePersistedState(state: PersistedState) {
  try {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ config: state.config, requestLogs: state.requestLogs.slice(0, MAX_LOGS) })
    );
  } catch {
    // ignore
  }
}

const DEFAULT_CONFIG: OIDCConfig = {
  baseUrl: 'https://oidctest.wsweet.org/',
  clientId: '',
  clientSecret: '',
  redirectUri: `${window.location.origin}/redirect.html`,
  scopes: ['openid', 'profile', 'email'],
  flowType: 'authorization_code',
  manualConfig: { authorizationEndpoint: '', tokenEndpoint: '', userinfoEndpoint: '', jwksUri: '', issuer: '' },
  useManualConfig: false,
};

const OIDCTestInterface: React.FC = () => {
  const { toast } = useToast();
  const persisted = useRef<PersistedState | null>(loadPersistedState());

  const [discovery, setDiscovery] = useState<DiscoveryDocument | null>(null);
  const [userInfo, setUserInfo] = useState<Record<string, unknown> | null>(null);
  const [config, setConfig] = useState<OIDCConfig>(() => persisted.current?.config ?? DEFAULT_CONFIG);
  const [tokens, setTokens] = useState<TokenResponse | null>(null);
  const [tokenExpiry, setTokenExpiry] = useState<number | null>(null);
  const [requestLogs, setRequestLogs] = useState<RequestLog[]>(() => persisted.current?.requestLogs ?? []);
  const [loading, setLoading] = useState<Record<string, boolean>>({});
  const [showSecret, setShowSecret] = useState(false);
  const [authUrl, setAuthUrl] = useState('');
  const [lastAuthCode, setLastAuthCode] = useState<string | null>(null);
  const [tokenExchangeFailed, setTokenExchangeFailed] = useState(false);
  const [activeTab, setActiveTab] = useState<TabValue>('setup');
  const [exportDialogOpen, setExportDialogOpen] = useState(false);

  useEffect(() => {
    savePersistedState({ config, requestLogs });
  }, [config, requestLogs]);

  const generateId = useCallback(() => {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    array[6] = (array[6] & 0x0f) | 0x40;
    array[8] = (array[8] & 0x3f) | 0x80;
    const hex = Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }, []);

  const addRequestLog = useCallback(
    (log: Omit<RequestLog, 'id' | 'timestamp'>) => {
      const newLog: RequestLog = { ...log, id: generateId(), timestamp: new Date() };
      setRequestLogs((prev) => [newLog, ...prev].slice(0, MAX_LOGS));
      return newLog.id;
    },
    [generateId]
  );

  const updateRequestLog = useCallback((id: string, response: RequestLog['response']) => {
    setRequestLogs((prev) => prev.map((l) => (l.id === id ? { ...l, response } : l)));
  }, []);

  const clearLogs = useCallback(() => {
    setRequestLogs([]);
    toast({ title: 'Logs cleared' });
  }, [toast]);

  const effectiveDiscovery = useMemo(() => {
    if (config.useManualConfig) {
      return {
        authorization_endpoint: config.manualConfig.authorizationEndpoint,
        token_endpoint: config.manualConfig.tokenEndpoint,
        userinfo_endpoint: config.manualConfig.userinfoEndpoint,
        jwks_uri: config.manualConfig.jwksUri,
        issuer: config.manualConfig.issuer,
      };
    }
    return discovery;
  }, [config.useManualConfig, config.manualConfig, discovery]);

  // ---- PKCE helpers ----
  const generateCodeVerifier = () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };
  const generateCodeChallenge = async (verifier: string) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    if (crypto.subtle) {
      const hash = await crypto.subtle.digest('SHA-256', data);
      return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    // Fallback SHA-256 (non-secure contexts)
    const K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);
    const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
    const ch = (x: number, y: number, z: number) => (x & y) ^ (~x & z);
    const maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z);
    const sigma0 = (x: number) => rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    const sigma1 = (x: number) => rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    const gamma0 = (x: number) => rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
    const gamma1 = (x: number) => rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10);
    const msgLen = data.length;
    const bitLen = msgLen * 8;
    const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLen);
    padded.set(data);
    padded[msgLen] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLen - 8, 0, false);
    view.setUint32(paddedLen - 4, bitLen, false);
    const W = new Uint32Array(64);
    for (let i = 0; i < padded.length; i += 64) {
      for (let t = 0; t < 16; t++) W[t] = view.getUint32(i + t * 4, false);
      for (let t = 16; t < 64; t++) W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
      let [a, b, c, d, e, f, g, h] = H;
      for (let t = 0; t < 64; t++) {
        const T1 = (h + sigma1(e) + ch(e, f, g) + K[t] + W[t]) >>> 0;
        const T2 = (sigma0(a) + maj(a, b, c)) >>> 0;
        h = g; g = f; f = e; e = (d + T1) >>> 0;
        d = c; c = b; b = a; a = (T1 + T2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    for (let i = 0; i < 8; i++) rv.setUint32(i * 4, H[i], false);
    return btoa(String.fromCharCode(...result)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  // ---- discovery ----
  const fetchDiscoveryDocument = async () => {
    if (!config.baseUrl) {
      toast({ title: 'Error', description: 'Please enter a base URL', variant: 'destructive' });
      return;
    }
    setLoading((p) => ({ ...p, discovery: true }));
    const discoveryUrl = `${config.baseUrl.replace(/\/$/, '')}/.well-known/openid-configuration`;
    const logId = addRequestLog({ method: 'GET', url: discoveryUrl, headers: { Accept: 'application/json' } });
    const startTime = Date.now();
    try {
      const response = await fetch(discoveryUrl);
      const duration = Date.now() - startTime;
      const responseText = await response.text();
      let responseData: ReturnType<typeof JSON.parse> = null;
      try { responseData = JSON.parse(responseText); } catch { /* non-JSON */ }
      updateRequestLog(logId, {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: responseData ? JSON.stringify(responseData, null, 2) : responseText,
        duration,
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} ${response.statusText}` + (responseData?.error ? `: ${responseData.error}` : ''));
      }
      if (!responseData) throw new Error('Discovery endpoint returned a non-JSON response');
      setDiscovery(responseData);
      setConfig((prev) => ({ ...prev, scopes: responseData.scopes_supported?.slice(0, 5) ?? prev.scopes }));
      setTokenExchangeFailed(false);
      toast({ title: 'Success', description: 'Discovery document loaded' });
      setActiveTab('config');
    } catch (error) {
      toast({
        title: 'Discovery failed',
        description: `${error instanceof Error ? error.message : 'Unknown error'}. You can enable Manual Configuration below to enter endpoints by hand.`,
        variant: 'destructive',
      });
    } finally {
      setLoading((p) => ({ ...p, discovery: false }));
    }
  };

  // ---- auth URL (redirect flows only) ----
  const generateAuthUrl = useCallback(async (): Promise<string | null> => {
    if (!effectiveDiscovery || !config.clientId) {
      toast({
        title: 'Error',
        description: config.useManualConfig
          ? 'Please fill in manual configuration and enter client ID first'
          : 'Please fetch discovery document and enter client ID first',
        variant: 'destructive',
      });
      return null;
    }
    const state = generateId();
    const nonce = generateId();
    const params = new URLSearchParams({
      response_type:
        config.flowType === 'authorization_code' ? 'code'
          : config.flowType === 'implicit' ? 'id_token token'
          : 'code id_token token',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scopes.join(' '),
      state,
      nonce,
    });
    if (config.flowType === 'authorization_code') {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);
      params.append('code_challenge', codeChallenge);
      params.append('code_challenge_method', 'S256');
      sessionStorage.setItem('code_verifier', codeVerifier);
    }
    sessionStorage.setItem('oidc_state', params.get('state')!);
    sessionStorage.setItem('oidc_nonce', params.get('nonce')!);
    const url = `${effectiveDiscovery.authorization_endpoint}?${params.toString()}`;
    setAuthUrl(url);
    return url;
  }, [effectiveDiscovery, config, generateId, toast]);

  // ---- auth code exchange ----
  const exchangeCodeForTokens = useCallback(
    async (code: string) => {
      if (!effectiveDiscovery?.token_endpoint) {
        toast({ title: 'Error', description: 'No token endpoint available', variant: 'destructive' });
        return;
      }
      setLoading((p) => ({ ...p, token: true }));
      setTokenExchangeFailed(false);
      const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: config.redirectUri });
      if (!config.clientSecret) body.append('client_id', config.clientId);
      const codeVerifier = sessionStorage.getItem('code_verifier');
      if (codeVerifier) body.append('code_verifier', codeVerifier);
      const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
      if (config.clientSecret) headers.Authorization = `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`;
      const logId = addRequestLog({ method: 'POST', url: effectiveDiscovery.token_endpoint, headers, body: body.toString() });
      const startTime = Date.now();
      try {
        const response = await fetch(effectiveDiscovery.token_endpoint, { method: 'POST', headers, body });
        const duration = Date.now() - startTime;
        const text = await response.text();
        let data: ReturnType<typeof JSON.parse> = null;
        try { data = JSON.parse(text); } catch { /* non-JSON */ }
        updateRequestLog(logId, {
          status: response.status,
          headers: Object.fromEntries(response.headers.entries()),
          body: data ? JSON.stringify(data, null, 2) : text,
          duration,
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}: ${data?.error || response.statusText}`);
        if (data.id_token) {
          const storedNonce = sessionStorage.getItem('oidc_nonce');
          if (storedNonce) {
            try {
              const payload = JSON.parse(atob(data.id_token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
              if (payload.nonce && payload.nonce !== storedNonce) throw new Error('Nonce mismatch in ID token - possible replay attack');
            } catch (e) {
              if (e instanceof Error && e.message.includes('Nonce mismatch')) throw e;
            }
          }
        }
        sessionStorage.removeItem('code_verifier');
        sessionStorage.removeItem('oidc_state');
        sessionStorage.removeItem('oidc_nonce');
        setTokens(data);
        setTokenExpiry(data.expires_in ? Date.now() + data.expires_in * 1000 : null);
        setTokenExchangeFailed(false);
        toast({ title: 'Success', description: 'Tokens exchanged successfully' });
        setActiveTab('tokens');
      } catch (error) {
        setTokenExchangeFailed(true);
        updateRequestLog(logId, { status: 0, headers: {}, body: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`, duration: Date.now() - startTime });
        toast({ title: 'Token Exchange Error', description: error instanceof Error ? error.message : 'Unknown error', variant: 'destructive' });
      } finally {
        setLoading((p) => ({ ...p, token: false }));
      }
    },
    [effectiveDiscovery, config, addRequestLog, updateRequestLog, toast]
  );

  // ---- client_credentials (direct POST, no redirect) ----
  const clientCredentialsToken = useCallback(async () => {
    if (!effectiveDiscovery?.token_endpoint || !config.clientId) {
      toast({ title: 'Error', description: 'Token endpoint and client ID are required', variant: 'destructive' });
      return;
    }
    setLoading((p) => ({ ...p, token: true }));
    const body = new URLSearchParams({ grant_type: 'client_credentials' });
    if (config.scopes.length) body.append('scope', config.scopes.join(' '));
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (config.clientSecret) headers.Authorization = `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`;
    else body.append('client_id', config.clientId);
    const logId = addRequestLog({ method: 'POST', url: effectiveDiscovery.token_endpoint, headers, body: body.toString() });
    const startTime = Date.now();
    try {
      const response = await fetch(effectiveDiscovery.token_endpoint, { method: 'POST', headers, body });
      const duration = Date.now() - startTime;
      const text = await response.text();
      let data: ReturnType<typeof JSON.parse> = null;
      try { data = JSON.parse(text); } catch { /* non-JSON */ }
      updateRequestLog(logId, {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: data ? JSON.stringify(data, null, 2) : text,
        duration,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${data?.error || response.statusText}`);
      setTokens(data);
      setTokenExpiry(data.expires_in ? Date.now() + data.expires_in * 1000 : null);
      toast({ title: 'Success', description: 'Client credentials token received' });
      setActiveTab('tokens');
    } catch (error) {
      toast({ title: 'Token Error', description: error instanceof Error ? error.message : 'Unknown error', variant: 'destructive' });
    } finally {
      setLoading((p) => ({ ...p, token: false }));
    }
  }, [effectiveDiscovery, config, addRequestLog, updateRequestLog, toast]);

  // ---- refresh token ----
  const refreshTokens = useCallback(async () => {
    if (!tokens?.refresh_token || !effectiveDiscovery?.token_endpoint) {
      toast({ title: 'Error', description: 'No refresh token or token endpoint available', variant: 'destructive' });
      return;
    }
    setLoading((p) => ({ ...p, token: true }));
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token! });
    if (config.scopes.length) body.append('scope', config.scopes.join(' '));
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (config.clientSecret) headers.Authorization = `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`;
    else body.append('client_id', config.clientId);
    const logId = addRequestLog({ method: 'POST', url: effectiveDiscovery.token_endpoint, headers, body: body.toString() });
    const startTime = Date.now();
    try {
      const response = await fetch(effectiveDiscovery.token_endpoint, { method: 'POST', headers, body });
      const duration = Date.now() - startTime;
      const text = await response.text();
      let data: ReturnType<typeof JSON.parse> = null;
      try { data = JSON.parse(text); } catch { /* non-JSON */ }
      updateRequestLog(logId, {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: data ? JSON.stringify(data, null, 2) : text,
        duration,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${data?.error || response.statusText}`);
      setTokens((prev) => ({ ...prev, ...data }));
      setTokenExpiry(data.expires_in ? Date.now() + data.expires_in * 1000 : null);
      toast({ title: 'Success', description: 'Tokens refreshed' });
    } catch (error) {
      toast({ title: 'Refresh Error', description: error instanceof Error ? error.message : 'Unknown error', variant: 'destructive' });
    } finally {
      setLoading((p) => ({ ...p, token: false }));
    }
  }, [tokens, effectiveDiscovery, config, addRequestLog, updateRequestLog, toast]);

  // ---- begin flow (dispatches by flow type) ----
  const beginFlow = async () => {
    if (config.flowType === 'client_credentials') {
      await clientCredentialsToken();
      return;
    }
    const url = await generateAuthUrl();
    if (!url) return;
    const popup = window.open(url, 'oidc-auth', 'width=500,height=600,scrollbars=yes,resizable=yes');
    if (!popup) {
      toast({
        title: 'Popup blocked',
        description: 'The auth popup was blocked by the browser. Allow popups for this site or use the generated URL below.',
        variant: 'destructive',
      });
      return;
    }
    const handleMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      const { type, data } = event.data;
      if (type !== 'OIDC_CALLBACK') return;
      window.removeEventListener('message', handleMessage);
      clearInterval(checkClosed);
      popup.close();
      const redirectLogId = generateId();
      setRequestLogs((prev) =>
        [
          {
            id: redirectLogId,
            timestamp: new Date(),
            method: 'REDIRECT',
            url: config.redirectUri,
            headers: {},
            body: 'Authorization callback received',
            response: { status: data.error ? 400 : 200, headers: {}, body: JSON.stringify(data, null, 2), duration: 0 },
          },
          ...prev,
        ].slice(0, MAX_LOGS)
      );
      if (data.error) {
        toast({ title: 'Authentication Error', description: data.error_description || data.error, variant: 'destructive' });
      } else if (data.code) {
        setLastAuthCode(data.code);
        exchangeCodeForTokens(data.code);
      } else if (data.access_token || data.id_token) {
        setTokens(data);
        setTokenExpiry(data.expires_in ? Date.now() + data.expires_in * 1000 : null);
        toast({ title: 'Success', description: 'Tokens received successfully' });
        setActiveTab('tokens');
      }
    };
    window.addEventListener('message', handleMessage);
    const checkClosed = setInterval(() => {
      if (popup.closed) {
        clearInterval(checkClosed);
        window.removeEventListener('message', handleMessage);
      }
    }, 1000);
  };

  // ---- userinfo ----
  const fetchUserInfo = async () => {
    if (!tokens?.access_token) {
      toast({ title: 'Error', description: 'No access token available', variant: 'destructive' });
      return;
    }
    const userinfoEndpoint = config.useManualConfig ? config.manualConfig.userinfoEndpoint : discovery?.userinfo_endpoint;
    if (!userinfoEndpoint) {
      toast({ title: 'Error', description: 'No userinfo endpoint available', variant: 'destructive' });
      return;
    }
    setLoading((p) => ({ ...p, userinfo: true }));
    const logId = addRequestLog({ method: 'GET', url: userinfoEndpoint, headers: { Authorization: `Bearer ${tokens.access_token}` } });
    const startTime = Date.now();
    try {
      const response = await fetch(userinfoEndpoint, { method: 'GET', headers: { Authorization: `Bearer ${tokens.access_token}` } });
      const text = await response.text();
      const duration = Date.now() - startTime;
      updateRequestLog(logId, {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: text,
        duration,
      });
      if (response.ok) {
        setUserInfo(JSON.parse(text));
        toast({ title: 'Success', description: 'UserInfo retrieved successfully' });
      } else {
        toast({ title: 'Error', description: `UserInfo request failed: ${response.status}`, variant: 'destructive' });
      }
    } catch (error) {
      toast({ title: 'Error', description: `Failed to fetch userinfo: ${error instanceof Error ? error.message : 'Unknown error'}`, variant: 'destructive' });
    } finally {
      setLoading((p) => ({ ...p, userinfo: false }));
    }
  };

  // ---- clipboard ----
  const copyToClipboard = useCallback(
    async (text: string) => {
      const ok = await copyText(text);
      if (ok) toast({ title: 'Copied', description: 'Copied to clipboard' });
      else toast({ title: 'Copy failed', description: 'Clipboard unavailable in this context', variant: 'destructive' });
    },
    [toast]
  );

  // ---- export ----
  const exportConfig = (includeSecrets: boolean) => {
    const sanitizeHeaders = (h: Record<string, string>) => (includeSecrets ? h : redactHeaders(h));
    const sanitizeConfig = includeSecrets ? config : { ...config, clientSecret: '[REDACTED]' };
    const sanitizeTokens = includeSecrets ? tokens : tokens ? {
      ...tokens,
      access_token: tokens.access_token ? '[REDACTED]' : undefined,
      id_token: tokens.id_token ? '[REDACTED]' : undefined,
      refresh_token: tokens.refresh_token ? '[REDACTED]' : undefined,
    } : null;
    const sanitizeLogs = requestLogs.map((l) => ({
      ...l,
      headers: sanitizeHeaders(l.headers),
      response: l.response ? { ...l.response, headers: sanitizeHeaders(l.response.headers) } : l.response,
    }));
    const exportData = {
      config: sanitizeConfig,
      discovery,
      tokens: sanitizeTokens,
      userInfo,
      requestLogs: sanitizeLogs,
      exportedAt: new Date().toISOString(),
      secretsIncluded: includeSecrets,
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `oidc-test-${new Date().toISOString().split('T')[0]}${includeSecrets ? '-WITH-SECRETS' : ''}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setExportDialogOpen(false);
    toast({ title: 'Exported', description: includeSecrets ? 'Export includes secrets — handle with care.' : 'Secrets redacted in export.' });
  };

  // ---- flow step + canBegin ----
  const currentStep: FlowStep = useMemo(() => {
    if (tokens) return 'tokens';
    if (config.clientId) return 'authenticate';
    if (discovery || config.useManualConfig) return 'configure';
    return 'discover';
  }, [tokens, config.clientId, discovery, config.useManualConfig]);

  const canBeginFlow = useMemo(() => {
    if (config.flowType === 'client_credentials') return Boolean(effectiveDiscovery?.token_endpoint && config.clientId);
    return Boolean((discovery || config.useManualConfig) && config.clientId);
  }, [config.flowType, effectiveDiscovery, config.clientId, discovery, config.useManualConfig]);

  // ---- keyboard shortcuts ----
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const typing = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable);
      if (typing) {
        if (e.key === 'Enter' && target.id === 'baseUrl' && !loading.discovery) {
          e.preventDefault();
          fetchDiscoveryDocument();
        }
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && canBeginFlow) {
        e.preventDefault();
        beginFlow();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canBeginFlow, loading.discovery, config, discovery, effectiveDiscovery]);

  // ---- token expiry ticker ----
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!tokenExpiry) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [tokenExpiry]);
  const expirySecondsLeft = tokenExpiry ? Math.max(0, Math.floor((tokenExpiry - now) / 1000)) : null;

  return (
    <div className="min-h-screen bg-background text-foreground p-4">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center py-8 relative">
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="w-64 h-64 bg-primary/5 rounded-full blur-3xl" />
          </div>
          <div className="absolute top-8 right-0">
            <Link
              to="/docs"
              className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-primary transition-colors px-3 py-1.5 rounded-md border border-border/50 hover:border-primary/50 hover:bg-primary/5"
            >
              <BookOpen className="h-4 w-4" />
              <span className="hidden sm:inline">Docs</span>
            </Link>
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
            OpenID Connect Provider Testing Tool
          </p>
        </div>

        <FlowStepper current={currentStep} />

        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as TabValue)} className="space-y-6">
          <TabsList className="grid w-full grid-cols-2 sm:grid-cols-4 bg-muted/50 backdrop-blur-sm border border-border/50 p-1 shadow-lg">
            <TabsTrigger value="setup" className="data-[state=active]:shadow-glow-primary data-[state=active]:bg-primary/10 transition-all duration-200">Provider Setup</TabsTrigger>
            <TabsTrigger value="config" className="data-[state=active]:shadow-glow-primary data-[state=active]:bg-primary/10 transition-all duration-200">Client Config</TabsTrigger>
            <TabsTrigger value="tokens" className="data-[state=active]:shadow-glow-primary data-[state=active]:bg-primary/10 transition-all duration-200">Tokens</TabsTrigger>
            <TabsTrigger value="logs" className="data-[state=active]:shadow-glow-primary data-[state=active]:bg-primary/10 transition-all duration-200">Request Logs</TabsTrigger>
          </TabsList>

          <TabsContent value="setup">
            <SetupTab
              config={config}
              setConfig={setConfig}
              discovery={discovery}
              loadingDiscovery={!!loading.discovery}
              onFetchDiscovery={fetchDiscoveryDocument}
              onCopy={copyToClipboard}
            />
          </TabsContent>

          <TabsContent value="config">
            <ConfigTab
              config={config}
              setConfig={setConfig}
              showSecret={showSecret}
              setShowSecret={setShowSecret}
              authUrl={authUrl}
              onGenerateAuthUrl={generateAuthUrl}
              onBeginFlow={beginFlow}
              canBeginFlow={canBeginFlow}
              onCopy={copyToClipboard}
            />
          </TabsContent>

          <TabsContent value="tokens">
            <TokensTab
              tokens={tokens}
              loadingToken={!!loading.token}
              loadingUserinfo={!!loading.userinfo}
              userInfo={userInfo}
              onFetchUserInfo={fetchUserInfo}
              onCopy={copyToClipboard}
              onToast={(t) => toast(t)}
              onRefresh={refreshTokens}
              onReexchange={() => lastAuthCode && exchangeCodeForTokens(lastAuthCode)}
              showReexchange={!!lastAuthCode && tokenExchangeFailed}
              expirySecondsLeft={expirySecondsLeft}
            />
          </TabsContent>

          <TabsContent value="logs">
            <LogsTab
              logs={requestLogs}
              onClear={clearLogs}
              onExport={() => setExportDialogOpen(true)}
            />
          </TabsContent>
        </Tabs>

        <p className="text-center text-xs text-muted-foreground pt-4">
          Secrets are masked in the UI and redacted from logs by default. Use Export → "Include secrets" to capture them.
        </p>
      </div>

      <ExportDialog open={exportDialogOpen} onOpenChange={setExportDialogOpen} onExport={exportConfig} />
    </div>
  );
};

export default OIDCTestInterface;
