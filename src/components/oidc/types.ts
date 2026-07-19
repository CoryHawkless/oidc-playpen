// Shared types for the OIDC test interface.

export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  scopes_supported?: string[];
  response_types_supported: string[];
  grant_types_supported?: string[];
  [key: string]: unknown;
}

export interface OIDCConfig {
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

export interface RequestLog {
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

export interface TokenResponse {
  access_token?: string;
  id_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
}

export type FlowStep = 'discover' | 'configure' | 'authenticate' | 'tokens';
export type TabValue = 'setup' | 'config' | 'tokens' | 'logs';

export const SECRET_TOKEN_FIELDS = new Set(['access_token', 'id_token', 'refresh_token']);
export const MAX_LOGS = 200;
export const STORAGE_KEY = 'oidc-playpen:state:v1';
