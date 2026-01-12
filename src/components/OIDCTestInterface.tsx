import React, { useState, useCallback, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { 
  Globe, 
  Key, 
  Shield, 
  Play, 
  Copy, 
  Eye, 
  EyeOff,
  CheckCircle,
  XCircle,
  Clock,
  Download,
  Loader2
} from 'lucide-react';

interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  scopes_supported?: string[];
  response_types_supported: string[];
  grant_types_supported?: string[];
  [key: string]: any;
}

interface OIDCConfig {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
  flowType: 'authorization_code' | 'implicit' | 'hybrid' | 'client_credentials';
  manualConfig: {
    authorizationEndpoint: string;
    tokenEndpoint: string;
    userinfoEndpoint: string;
    jwksUri: string;
    issuer: string;
  };
  useManualConfig: boolean;
}

interface RequestLog {
  id: string;
  timestamp: Date;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  response?: {
    status: number;
    headers: Record<string, string>;
    body: string;
    duration: number;
  };
}

interface TokenResponse {
  access_token?: string;
  id_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
}

const OIDCTestInterface: React.FC = () => {
  const { toast } = useToast();
  const [discovery, setDiscovery] = useState<DiscoveryDocument | null>(null);
  const [userInfo, setUserInfo] = useState<Record<string, any> | null>(null);
  const [config, setConfig] = useState<OIDCConfig>({
    baseUrl: 'https://oidctest.wsweet.org/',
    clientId: '',
    clientSecret: '',
    redirectUri: `${window.location.origin}/redirect.html`,
    scopes: ['openid', 'profile', 'email'],
    flowType: 'authorization_code',
    manualConfig: {
      authorizationEndpoint: '',
      tokenEndpoint: '',
      userinfoEndpoint: '',
      jwksUri: '',
      issuer: ''
    },
    useManualConfig: false
  });
  const [tokens, setTokens] = useState<TokenResponse | null>(null);
  const [requestLogs, setRequestLogs] = useState<RequestLog[]>([]);
  const [loading, setLoading] = useState<Record<string, boolean>>({});
  const [showSecret, setShowSecret] = useState(false);
  const [authUrl, setAuthUrl] = useState('');
  const popupRef = useRef<Window | null>(null);

  // Fallback for crypto.randomUUID (not available in non-secure contexts)
  const generateId = useCallback(() => {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    // Fallback using crypto.getRandomValues
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    array[6] = (array[6] & 0x0f) | 0x40; // Version 4
    array[8] = (array[8] & 0x3f) | 0x80; // Variant 10
    const hex = Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }, []);

  const addRequestLog = useCallback((log: Omit<RequestLog, 'id' | 'timestamp'>) => {
    const newLog: RequestLog = {
      ...log,
      id: generateId(),
      timestamp: new Date()
    };
    setRequestLogs(prev => [newLog, ...prev]);
    return newLog.id;
  }, [generateId]);

  const updateRequestLog = useCallback((id: string, response: RequestLog['response']) => {
    setRequestLogs(prev => prev.map(log => 
      log.id === id ? { ...log, response } : log
    ));
  }, []);

  const fetchDiscoveryDocument = async () => {
    if (!config.baseUrl) {
      toast({
        title: "Error",
        description: "Please enter a base URL",
        variant: "destructive"
      });
      return;
    }

    setLoading(prev => ({ ...prev, discovery: true }));
    const discoveryUrl = `${config.baseUrl.replace(/\/$/, '')}/.well-known/openid-configuration`;
    
    const logId = addRequestLog({
      method: 'GET',
      url: discoveryUrl,
      headers: { 'Accept': 'application/json' }
    });

    const startTime = Date.now();

    try {
      const response = await fetch(discoveryUrl);
      const duration = Date.now() - startTime;
      const responseData = await response.json();

      updateRequestLog(logId, {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: JSON.stringify(responseData, null, 2),
        duration
      });

      if (response.ok) {
        setDiscovery(responseData);
        setConfig(prev => ({
          ...prev,
          scopes: responseData.scopes_supported?.slice(0, 5) || prev.scopes
        }));
        toast({
          title: "Success",
          description: "Discovery document loaded successfully"
        });
      } else {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
    } catch (error) {
      updateRequestLog(logId, {
        status: 0,
        headers: {},
        body: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        duration: Date.now() - startTime
      });
      
      // Auto-populate manual config with likely endpoints
      const baseUrl = config.baseUrl.replace(/\/$/, '');
      setConfig(prev => ({
        ...prev,
        useManualConfig: true,
        manualConfig: {
          authorizationEndpoint: `${baseUrl}/oauth/authorize`,
          tokenEndpoint: `${baseUrl}/oauth/token`,
          userinfoEndpoint: `${baseUrl}/oauth/userinfo`,
          jwksUri: `${baseUrl}/.well-known/jwks.json`,
          issuer: baseUrl
        }
      }));
      
      toast({
        title: "Auto-discovery failed",
        description: `CORS error detected. Manual config auto-populated with standard endpoints.`,
        variant: "destructive"
      });
    } finally {
      setLoading(prev => ({ ...prev, discovery: false }));
    }
  };

  const generateAuthUrl = useCallback(async () => {
    const effectiveDiscovery = config.useManualConfig 
      ? {
          authorization_endpoint: config.manualConfig.authorizationEndpoint,
          token_endpoint: config.manualConfig.tokenEndpoint,
          userinfo_endpoint: config.manualConfig.userinfoEndpoint,
          jwks_uri: config.manualConfig.jwksUri,
          issuer: config.manualConfig.issuer
        }
      : discovery;

    if (!effectiveDiscovery || !config.clientId) {
      toast({
        title: "Error",
        description: config.useManualConfig 
          ? "Please fill in manual configuration and enter client ID first"
          : "Please fetch discovery document and enter client ID first",
        variant: "destructive"
      });
      return;
    }

    const state = generateId();
    const nonce = generateId();

    const params = new URLSearchParams({
      response_type: config.flowType === 'authorization_code' ? 'code' : 
                    config.flowType === 'implicit' ? 'id_token token' : 'code id_token token',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scopes.join(' '),
      state,
      nonce
    });
    // Add PKCE for authorization code flow
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
  }, [discovery, config, generateId]);

  const generateCodeVerifier = () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };

  const generateCodeChallenge = async (verifier: string) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    
    // Check if crypto.subtle is available (requires secure context)
    if (crypto.subtle) {
      const hash = await crypto.subtle.digest('SHA-256', data);
      return btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    }
    
    // Fallback: simple SHA-256 implementation for non-secure contexts
    // Using a basic implementation since crypto.subtle is unavailable
    const sha256Fallback = async (message: Uint8Array): Promise<Uint8Array> => {
      // Constants for SHA-256
      const K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
      ]);
      
      const H = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
      ]);
      
      const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
      const ch = (x: number, y: number, z: number) => (x & y) ^ (~x & z);
      const maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z);
      const sigma0 = (x: number) => rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
      const sigma1 = (x: number) => rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
      const gamma0 = (x: number) => rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
      const gamma1 = (x: number) => rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10);
      
      // Padding
      const msgLen = message.length;
      const bitLen = msgLen * 8;
      // Calculate padded length: must be multiple of 64 bytes, with room for 1 byte (0x80) + 8 bytes (length)
      const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
      const padded = new Uint8Array(paddedLen);
      padded.set(message);
      padded[msgLen] = 0x80;
      // Store bit length as 64-bit big-endian at the end
      const view = new DataView(padded.buffer);
      view.setUint32(paddedLen - 8, 0, false); // High 32 bits (0 for messages < 512MB)
      view.setUint32(paddedLen - 4, bitLen, false); // Low 32 bits
      
      // Process blocks
      const W = new Uint32Array(64);
      for (let i = 0; i < padded.length; i += 64) {
        for (let t = 0; t < 16; t++) {
          W[t] = view.getUint32(i + t * 4, false);
        }
        for (let t = 16; t < 64; t++) {
          W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
        }
        
        let [a, b, c, d, e, f, g, h] = H;
        for (let t = 0; t < 64; t++) {
          const T1 = (h + sigma1(e) + ch(e, f, g) + K[t] + W[t]) >>> 0;
          const T2 = (sigma0(a) + maj(a, b, c)) >>> 0;
          h = g; g = f; f = e; e = (d + T1) >>> 0;
          d = c; c = b; b = a; a = (T1 + T2) >>> 0;
        }
        H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
      }
      
      const result = new Uint8Array(32);
      const resultView = new DataView(result.buffer);
      for (let i = 0; i < 8; i++) {
        resultView.setUint32(i * 4, H[i], false);
      }
      return result;
    };
    
    const hash = await sha256Fallback(data);
    return btoa(String.fromCharCode(...hash))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };

  const beginFlow = async () => {
    const url = await generateAuthUrl();
    if (!url) return;

    const popup = window.open(
      url,
      'oidc-auth',
      'width=500,height=600,scrollbars=yes,resizable=yes'
    );
    
    popupRef.current = popup;

    // Listen for message from redirect page
    const handleMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      
      const { type, data } = event.data;
      
      if (type === 'OIDC_CALLBACK') {
        window.removeEventListener('message', handleMessage);
        popup?.close();

        // Log the redirect callback response
        const redirectLogId = generateId();
        setRequestLogs(prev => [...prev, {
          id: redirectLogId,
          timestamp: new Date(),
          method: 'REDIRECT',
          url: config.redirectUri,
          headers: {},
          body: 'Authorization callback received',
          response: {
            status: data.error ? 400 : 200,
            headers: {},
            body: JSON.stringify(data, null, 2),
            duration: 0
          }
        }]);
        
        if (data.error) {
          toast({
            title: "Authentication Error",
            description: data.error_description || data.error,
            variant: "destructive"
          });
        } else if (data.code) {
          exchangeCodeForTokens(data.code);
        } else if (data.access_token || data.id_token) {
          setTokens(data);
          toast({
            title: "Success",
            description: "Tokens received successfully"
          });
        }
      }
    };

    window.addEventListener('message', handleMessage);

    // Cleanup if popup is closed manually
    const checkClosed = setInterval(() => {
      if (popup?.closed) {
        clearInterval(checkClosed);
        window.removeEventListener('message', handleMessage);
      }
    }, 1000);
  };

  const exchangeCodeForTokens = async (code: string) => {
    const effectiveDiscovery = config.useManualConfig 
      ? {
          authorization_endpoint: config.manualConfig.authorizationEndpoint,
          token_endpoint: config.manualConfig.tokenEndpoint,
          userinfo_endpoint: config.manualConfig.userinfoEndpoint,
          jwks_uri: config.manualConfig.jwksUri,
          issuer: config.manualConfig.issuer
        }
      : discovery;

    if (!effectiveDiscovery?.token_endpoint) return;

    setLoading(prev => ({ ...prev, token: true }));
    
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.redirectUri
    });

    // Only include client_id in body for public clients (no client secret)
    if (!config.clientSecret) {
      body.append('client_id', config.clientId);
    }

    // Always include code_verifier for PKCE
    const codeVerifier = sessionStorage.getItem('code_verifier');
    if (codeVerifier) {
      body.append('code_verifier', codeVerifier);
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded'
    };

    if (config.clientSecret) {
      headers.Authorization = `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`;
    }

    const logId = addRequestLog({
      method: 'POST',
      url: effectiveDiscovery.token_endpoint,
      headers,
      body: body.toString()
    });

    const startTime = Date.now();

    try {
      const response = await fetch(effectiveDiscovery.token_endpoint, {
        method: 'POST',
        headers,
        body
      });

      const duration = Date.now() - startTime;
      const responseData = await response.json();

      updateRequestLog(logId, {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: JSON.stringify(responseData, null, 2),
        duration
      });

      if (response.ok) {
        // Validate nonce in id_token if present (OIDC best practice)
        if (responseData.id_token) {
          const storedNonce = sessionStorage.getItem('oidc_nonce');
          if (storedNonce) {
            try {
              const payload = JSON.parse(atob(responseData.id_token.split('.')[1]));
              if (payload.nonce && payload.nonce !== storedNonce) {
                throw new Error('Nonce mismatch in ID token - possible replay attack');
              }
            } catch (e) {
              if (e instanceof Error && e.message.includes('Nonce mismatch')) {
                throw e;
              }
              // Ignore parsing errors for non-JWT tokens
            }
          }
        }
        
        // Clear sensitive session data after successful exchange (OIDC best practice)
        sessionStorage.removeItem('code_verifier');
        sessionStorage.removeItem('oidc_state');
        sessionStorage.removeItem('oidc_nonce');
        
        setTokens(responseData);
        toast({
          title: "Success",
          description: "Tokens exchanged successfully"
        });
      } else {
        throw new Error(`HTTP ${response.status}: ${responseData.error || response.statusText}`);
      }
    } catch (error) {
      updateRequestLog(logId, {
        status: 0,
        headers: {},
        body: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        duration: Date.now() - startTime
      });
      
      toast({
        title: "Token Exchange Error",
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: "destructive"
      });
    } finally {
      setLoading(prev => ({ ...prev, token: false }));
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Text copied to clipboard"
    });
  };

  const fetchUserInfo = async () => {
    if (!tokens?.access_token) {
      toast({
        title: "Error",
        description: "No access token available",
        variant: "destructive"
      });
      return;
    }

    const userinfoEndpoint = config.useManualConfig 
      ? config.manualConfig.userinfoEndpoint 
      : discovery?.userinfo_endpoint;

    if (!userinfoEndpoint) {
      toast({
        title: "Error",
        description: "No userinfo endpoint available",
        variant: "destructive"
      });
      return;
    }

    setLoading(prev => ({ ...prev, userinfo: true }));
    
    const logId = addRequestLog({
      method: 'GET',
      url: userinfoEndpoint,
      headers: {
        'Authorization': `Bearer ${tokens.access_token}`
      }
    });

    const startTime = Date.now();

    try {
      const response = await fetch(userinfoEndpoint, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${tokens.access_token}`
        }
      });

      const responseText = await response.text();
      const duration = Date.now() - startTime;
      
      updateRequestLog(logId, {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: responseText,
        duration
      });

      if (response.ok) {
        const userInfoData = JSON.parse(responseText);
        setUserInfo(userInfoData);
        toast({
          title: "Success",
          description: "UserInfo retrieved successfully"
        });
      } else {
        toast({
          title: "Error",
          description: `UserInfo request failed: ${response.status}`,
          variant: "destructive"
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: `Failed to fetch userinfo: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: "destructive"
      });
    } finally {
      setLoading(prev => ({ ...prev, userinfo: false }));
    }
  };

  const exportConfig = () => {
    const exportData = {
      config,
      discovery,
      tokens,
      userInfo,
      requestLogs,
      timestamp: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `oidc-test-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-background text-foreground p-4">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center py-8">
          <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-primary to-primary-glow bg-clip-text text-transparent">
            OIDC Test Interface
          </h1>
          <p className="text-lg text-muted-foreground">
            Browser-based OpenID Connect provider testing tool
          </p>
        </div>

        <Tabs defaultValue="setup" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="setup">Provider Setup</TabsTrigger>
            <TabsTrigger value="config">Client Config</TabsTrigger>
            <TabsTrigger value="tokens">Tokens</TabsTrigger>
            <TabsTrigger value="logs">Request Logs</TabsTrigger>
          </TabsList>

          {/* Provider Setup Tab */}
          <TabsContent value="setup">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Provider Discovery
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="baseUrl">Provider Base URL</Label>
                  <div className="flex gap-2">
                    <Input
                      id="baseUrl"
                      placeholder="https://accounts.google.com"
                      value={config.baseUrl}
                      onChange={(e) => setConfig(prev => ({ ...prev, baseUrl: e.target.value }))}
                      className="flex-1"
                    />
                    <Button 
                      onClick={fetchDiscoveryDocument}
                      disabled={loading.discovery}
                      className="min-w-[120px]"
                    >
                      {loading.discovery ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <>
                          <Globe className="h-4 w-4 mr-2" />
                          Fetch Config
                        </>
                      )}
                    </Button>
                  </div>
                </div>

                {discovery && (
                  <div className="space-y-4">
                    <Alert>
                      <CheckCircle className="h-4 w-4" />
                      <AlertDescription>
                        Discovery document loaded successfully from {discovery.issuer}
                      </AlertDescription>
                    </Alert>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <Label className="text-sm font-medium">Authorization Endpoint</Label>
                        <div className="flex items-center gap-2 mt-1">
                          <code className="text-xs bg-code-bg p-2 rounded border border-code-border flex-1 truncate">
                            {discovery.authorization_endpoint}
                          </code>
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => copyToClipboard(discovery.authorization_endpoint)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                      
                      <div>
                        <Label className="text-sm font-medium">Token Endpoint</Label>
                        <div className="flex items-center gap-2 mt-1">
                          <code className="text-xs bg-code-bg p-2 rounded border border-code-border flex-1 truncate">
                            {discovery.token_endpoint}
                          </code>
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => copyToClipboard(discovery.token_endpoint)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    </div>

                    {discovery.scopes_supported && (
                      <div>
                        <Label className="text-sm font-medium">Supported Scopes</Label>
                        <div className="flex flex-wrap gap-1 mt-2">
                          {discovery.scopes_supported.map(scope => (
                            <Badge key={scope} variant="secondary" className="text-xs">
                              {scope}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                   </div>
                 )}

                 {/* Manual Configuration Toggle */}
                 <div className="space-y-4 pt-6 border-t border-border">
                   <div className="flex items-center space-x-2">
                     <input
                       type="checkbox"
                       id="useManualConfig"
                       checked={config.useManualConfig}
                       onChange={(e) => setConfig(prev => ({ ...prev, useManualConfig: e.target.checked }))}
                       className="rounded"
                     />
                     <Label htmlFor="useManualConfig" className="text-sm font-medium">
                       Use Manual Configuration (bypass CORS)
                     </Label>
                   </div>

                   {config.useManualConfig && (
                     <div className="space-y-4 bg-muted/50 p-4 rounded-lg">
                       <h4 className="font-semibold text-sm">Manual OIDC Endpoints</h4>
                       <div className="grid grid-cols-1 gap-4">
                         <div className="space-y-2">
                           <Label htmlFor="issuer">Issuer</Label>
                           <Input
                             id="issuer"
                             placeholder="https://auth.hawkvelt.id.au/application/o/flask2"
                             value={config.manualConfig.issuer}
                             onChange={(e) => setConfig(prev => ({
                               ...prev,
                               manualConfig: { ...prev.manualConfig, issuer: e.target.value }
                             }))}
                           />
                         </div>
                         <div className="space-y-2">
                           <Label htmlFor="authEndpoint">Authorization Endpoint</Label>
                           <Input
                             id="authEndpoint"
                             placeholder="https://auth.hawkvelt.id.au/application/o/flask2/authorize"
                             value={config.manualConfig.authorizationEndpoint}
                             onChange={(e) => setConfig(prev => ({
                               ...prev,
                               manualConfig: { ...prev.manualConfig, authorizationEndpoint: e.target.value }
                             }))}
                           />
                         </div>
                         <div className="space-y-2">
                           <Label htmlFor="tokenEndpoint">Token Endpoint</Label>
                           <Input
                             id="tokenEndpoint"
                             placeholder="https://auth.hawkvelt.id.au/application/o/flask2/token"
                             value={config.manualConfig.tokenEndpoint}
                             onChange={(e) => setConfig(prev => ({
                               ...prev,
                               manualConfig: { ...prev.manualConfig, tokenEndpoint: e.target.value }
                             }))}
                           />
                         </div>
                         <div className="space-y-2">
                           <Label htmlFor="userinfoEndpoint">Userinfo Endpoint</Label>
                           <Input
                             id="userinfoEndpoint"
                             placeholder="https://auth.hawkvelt.id.au/application/o/flask2/userinfo"
                             value={config.manualConfig.userinfoEndpoint}
                             onChange={(e) => setConfig(prev => ({
                               ...prev,
                               manualConfig: { ...prev.manualConfig, userinfoEndpoint: e.target.value }
                             }))}
                           />
                         </div>
                         <div className="space-y-2">
                           <Label htmlFor="jwksUri">JWKS URI</Label>
                           <Input
                             id="jwksUri"
                             placeholder="https://auth.hawkvelt.id.au/application/o/flask2/jwks"
                             value={config.manualConfig.jwksUri}
                             onChange={(e) => setConfig(prev => ({
                               ...prev,
                               manualConfig: { ...prev.manualConfig, jwksUri: e.target.value }
                             }))}
                           />
                         </div>
                       </div>
                     </div>
                   )}
                 </div>
               </CardContent>
             </Card>
           </TabsContent>

          {/* Client Config Tab */}
          <TabsContent value="config">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Key className="h-5 w-5" />
                  Client Configuration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="clientId">Client ID</Label>
                    <Input
                      id="clientId"
                      placeholder="your-client-id"
                      value={config.clientId}
                      onChange={(e) => setConfig(prev => ({ ...prev, clientId: e.target.value }))}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="clientSecret">Client Secret (Optional)</Label>
                    <div className="relative">
                      <Input
                        id="clientSecret"
                        type={showSecret ? "text" : "password"}
                        placeholder="your-client-secret"
                        value={config.clientSecret}
                        onChange={(e) => setConfig(prev => ({ ...prev, clientSecret: e.target.value }))}
                        className="pr-10"
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3"
                        onClick={() => setShowSecret(!showSecret)}
                      >
                        {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="flowType">Flow Type</Label>
                  <Select
                    value={config.flowType}
                    onValueChange={(value: OIDCConfig['flowType']) => 
                      setConfig(prev => ({ ...prev, flowType: value }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="authorization_code">Authorization Code + PKCE (Recommended)</SelectItem>
                      <SelectItem value="implicit">Implicit Flow (Deprecated - RFC 9700)</SelectItem>
                      <SelectItem value="hybrid">Hybrid Flow</SelectItem>
                      <SelectItem value="client_credentials">Client Credentials</SelectItem>
                    </SelectContent>
                  </Select>
                  {config.flowType === 'implicit' && (
                    <p className="text-xs text-destructive mt-1">
                      ⚠️ Implicit flow is deprecated per RFC 9700. Use Authorization Code + PKCE instead.
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="redirectUri">Redirect URI</Label>
                  <Input
                    id="redirectUri"
                    value={config.redirectUri}
                    onChange={(e) => setConfig(prev => ({ ...prev, redirectUri: e.target.value }))}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="scopes">Scopes</Label>
                  <Input
                    id="scopes"
                    placeholder="openid profile email"
                    value={config.scopes.join(' ')}
                    onChange={(e) => setConfig(prev => ({ 
                      ...prev, 
                      scopes: e.target.value.split(' ').filter(Boolean) 
                    }))}
                  />
                </div>

                {authUrl && (
                  <div className="space-y-2">
                    <Label>Generated Authorization URL</Label>
                    <div className="flex gap-2">
                      <Textarea
                        value={authUrl}
                        readOnly
                        className="font-mono text-xs"
                        rows={3}
                      />
                      <div className="flex flex-col gap-2">
                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={() => copyToClipboard(authUrl)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={() => window.open(authUrl, '_blank')}
                        >
                          <Globe className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex gap-2 pt-4">
                  <Button onClick={generateAuthUrl} variant="outline">
                    Generate URL
                  </Button>
                   <Button 
                     onClick={beginFlow}
                     disabled={(!discovery && !config.useManualConfig) || !config.clientId}
                     className="flex-1"
                   >
                    <Play className="h-4 w-4 mr-2" />
                    Begin Flow
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tokens Tab */}
          <TabsContent value="tokens">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Token Display
                </CardTitle>
              </CardHeader>
              <CardContent>
              {tokens ? (
                  <div className="space-y-6">
                    <div className="space-y-4">
                      {Object.entries(tokens).map(([key, value]) => (
                        <div key={key} className="space-y-2">
                          <div className="flex items-center justify-between">
                            <Label className="text-sm font-medium capitalize">
                              {key.replace(/_/g, ' ')}
                            </Label>
                            <Button 
                              size="sm" 
                              variant="outline"
                              onClick={() => copyToClipboard(String(value))}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </div>
                          <pre className="text-xs bg-code-bg p-3 rounded border border-code-border overflow-x-auto">
                            {(() => {
                              if (typeof value === 'string' && value.split('.').length === 3) {
                                try {
                                  // Decode base64url to base64, then decode
                                  const decodeBase64Url = (str: string) => {
                                    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
                                    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
                                    return atob(padded);
                                  };
                                  const parts = value.split('.');
                                  return JSON.stringify(
                                    {
                                      header: JSON.parse(decodeBase64Url(parts[0])),
                                      payload: JSON.parse(decodeBase64Url(parts[1])),
                                      signature: parts[2]
                                    },
                                    null,
                                    2
                                  );
                                } catch {
                                  return String(value);
                                }
                              }
                              return String(value);
                            })()}
                          </pre>
                        </div>
                      ))}
                    </div>

                    {/* UserInfo Section */}
                    <div className="border-t border-border pt-6">
                      <div className="flex items-center justify-between mb-4">
                        <Label className="text-sm font-medium">UserInfo Endpoint</Label>
                        <Button 
                          onClick={fetchUserInfo}
                          disabled={loading.userinfo || !tokens.access_token}
                          size="sm"
                        >
                          {loading.userinfo ? (
                            <Loader2 className="h-4 w-4 animate-spin mr-2" />
                          ) : (
                            <Globe className="h-4 w-4 mr-2" />
                          )}
                          Fetch UserInfo
                        </Button>
                      </div>
                      
                      {userInfo ? (
                        <pre className="text-xs bg-code-bg p-3 rounded border border-code-border overflow-x-auto">
                          {JSON.stringify(userInfo, null, 2)}
                        </pre>
                      ) : (
                        <div className="text-sm text-muted-foreground">
                          Click "Fetch UserInfo" to query the userinfo endpoint with the access token.
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    No tokens received yet. Complete the authentication flow to see tokens here.
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Logs Tab */}
          <TabsContent value="logs">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Clock className="h-5 w-5" />
                    Logs
                  </div>
                  <Button onClick={exportConfig} variant="outline" size="sm">
                    <Download className="h-4 w-4 mr-2" />
                    Export
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {requestLogs.length > 0 ? (
                  <div className="space-y-4">
                    {[...requestLogs].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime()).map((log) => {
                      const isRedirect = log.method === 'REDIRECT';
                      return (
                        <div 
                          key={log.id} 
                          className={`border rounded p-4 space-y-2 ${
                            isRedirect 
                              ? 'border-amber-500/50 bg-amber-500/5' 
                              : 'border-border'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Badge 
                                variant={log.response?.status && log.response.status < 400 ? "default" : "destructive"}
                                className={isRedirect ? 'bg-amber-600 hover:bg-amber-700' : ''}
                              >
                                {log.method}
                              </Badge>
                              <span className="font-mono text-sm truncate max-w-md">{log.url}</span>
                            </div>
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                              {log.response?.status && (
                                <Badge variant={log.response.status < 400 ? "default" : "destructive"}>
                                  {log.response.status}
                                </Badge>
                              )}
                              {log.response?.duration !== undefined && log.response.duration > 0 && (
                                <span>{log.response.duration}ms</span>
                              )}
                              <span>{log.timestamp.toLocaleTimeString()}</span>
                            </div>
                          </div>

                          {/* Full Request URL */}
                          <details className="text-sm">
                            <summary className="cursor-pointer text-muted-foreground">Request URL</summary>
                            <pre className="mt-2 bg-code-bg p-3 rounded border border-code-border overflow-x-auto text-xs break-all whitespace-pre-wrap">
                              {log.url}
                            </pre>
                          </details>

                          {/* Request Headers */}
                          {Object.keys(log.headers).length > 0 && (
                            <details className="text-sm">
                              <summary className="cursor-pointer text-muted-foreground">Request Headers</summary>
                              <pre className="mt-2 bg-code-bg p-3 rounded border border-code-border overflow-x-auto text-xs">
                                {JSON.stringify(log.headers, null, 2)}
                              </pre>
                            </details>
                          )}

                          {/* Request Body/Payload */}
                          {log.body && (
                            <details className="text-sm">
                              <summary className="cursor-pointer text-muted-foreground">Request Payload</summary>
                              <pre className="mt-2 bg-code-bg p-3 rounded border border-code-border overflow-x-auto text-xs">
                                {log.body}
                              </pre>
                            </details>
                          )}

                          {/* Response Headers */}
                          {log.response && Object.keys(log.response.headers).length > 0 && (
                            <details className="text-sm">
                              <summary className="cursor-pointer text-muted-foreground">Response Headers</summary>
                              <pre className="mt-2 bg-code-bg p-3 rounded border border-code-border overflow-x-auto text-xs">
                                {JSON.stringify(log.response.headers, null, 2)}
                              </pre>
                            </details>
                          )}

                          {/* Response Body */}
                          {log.response && (
                            <details className="text-sm">
                              <summary className="cursor-pointer text-muted-foreground">
                                {isRedirect ? 'Callback Data' : 'Response Body'}
                              </summary>
                              <pre className="mt-2 bg-code-bg p-3 rounded border border-code-border overflow-x-auto text-xs">
                                {log.response.body}
                              </pre>
                            </details>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    No requests logged yet. Interact with the OIDC provider to see request logs here.
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default OIDCTestInterface;