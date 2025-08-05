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
  const [config, setConfig] = useState<OIDCConfig>({
    baseUrl: '',
    clientId: '',
    clientSecret: '',
    redirectUri: `${window.location.origin}/redirect.html`,
    scopes: ['openid', 'profile', 'email'],
    flowType: 'authorization_code'
  });
  const [tokens, setTokens] = useState<TokenResponse | null>(null);
  const [requestLogs, setRequestLogs] = useState<RequestLog[]>([]);
  const [loading, setLoading] = useState<Record<string, boolean>>({});
  const [showSecret, setShowSecret] = useState(false);
  const [authUrl, setAuthUrl] = useState('');
  const popupRef = useRef<Window | null>(null);

  const addRequestLog = useCallback((log: Omit<RequestLog, 'id' | 'timestamp'>) => {
    const newLog: RequestLog = {
      ...log,
      id: crypto.randomUUID(),
      timestamp: new Date()
    };
    setRequestLogs(prev => [newLog, ...prev]);
    return newLog.id;
  }, []);

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
      
      toast({
        title: "Error",
        description: `Failed to fetch discovery document: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: "destructive"
      });
    } finally {
      setLoading(prev => ({ ...prev, discovery: false }));
    }
  };

  const generateAuthUrl = useCallback(async () => {
    if (!discovery || !config.clientId) {
      toast({
        title: "Error",
        description: "Please fetch discovery document and enter client ID first",
        variant: "destructive"
      });
      return;
    }

    const params = new URLSearchParams({
      response_type: config.flowType === 'authorization_code' ? 'code' : 
                    config.flowType === 'implicit' ? 'id_token token' : 'code id_token token',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scopes.join(' '),
      state: crypto.randomUUID(),
      nonce: crypto.randomUUID()
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

    const url = `${discovery.authorization_endpoint}?${params.toString()}`;
    setAuthUrl(url);
    return url;
  }, [discovery, config]);

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
    const hash = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)))
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
    if (!discovery?.token_endpoint) return;

    setLoading(prev => ({ ...prev, token: true }));
    
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.redirectUri,
      client_id: config.clientId
    });

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
      url: discovery.token_endpoint,
      headers,
      body: body.toString()
    });

    const startTime = Date.now();

    try {
      const response = await fetch(discovery.token_endpoint, {
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

  const exportConfig = () => {
    const exportData = {
      config,
      discovery,
      tokens,
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
                      <SelectItem value="authorization_code">Authorization Code + PKCE</SelectItem>
                      <SelectItem value="implicit">Implicit Flow</SelectItem>
                      <SelectItem value="hybrid">Hybrid Flow</SelectItem>
                      <SelectItem value="client_credentials">Client Credentials</SelectItem>
                    </SelectContent>
                  </Select>
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
                    disabled={!discovery || !config.clientId}
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
                          {typeof value === 'string' && value.includes('.') ? 
                            // JWT token - decode and display
                            JSON.stringify(
                              {
                                header: JSON.parse(atob(value.split('.')[0])),
                                payload: JSON.parse(atob(value.split('.')[1])),
                                signature: value.split('.')[2]
                              }, 
                              null, 
                              2
                            ) : 
                            String(value)
                          }
                        </pre>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    No tokens received yet. Complete the authentication flow to see tokens here.
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Request Logs Tab */}
          <TabsContent value="logs">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Clock className="h-5 w-5" />
                    Request Logs
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
                    {requestLogs.map((log) => (
                      <div key={log.id} className="border border-border rounded p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge variant={log.response?.status && log.response.status < 400 ? "default" : "destructive"}>
                              {log.method}
                            </Badge>
                            <span className="font-mono text-sm">{log.url}</span>
                          </div>
                          <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            {log.response?.status && (
                              <Badge variant={log.response.status < 400 ? "default" : "destructive"}>
                                {log.response.status}
                              </Badge>
                            )}
                            {log.response?.duration && (
                              <span>{log.response.duration}ms</span>
                            )}
                            <span>{log.timestamp.toLocaleTimeString()}</span>
                          </div>
                        </div>
                        
                        {log.response && (
                          <details className="text-sm">
                            <summary className="cursor-pointer text-muted-foreground">
                              Response Details
                            </summary>
                            <pre className="mt-2 bg-code-bg p-3 rounded border border-code-border overflow-x-auto text-xs">
                              {log.response.body}
                            </pre>
                          </details>
                        )}
                      </div>
                    ))}
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