import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { Shield, Play, Copy, Globe, Loader2, RefreshCw, Clock, Lock } from 'lucide-react';
import JsonHighlight from '@/components/JsonHighlight';
import MaskedValue from '@/components/MaskedValue';
import { decodeJwt, isJwtLike } from '@/lib/oidc-utils';
import type { TokenResponse } from './types';
import { SECRET_TOKEN_FIELDS } from './types';

interface TokensTabProps {
  tokens: TokenResponse | null;
  loadingToken: boolean;
  loadingUserinfo: boolean;
  userInfo: Record<string, unknown> | null;
  onFetchUserInfo: () => void;
  onCopy: (text: string) => void;
  onToast: (t: { title: string; variant?: 'destructive' }) => void;
  onRefresh: () => void;
  onReexchange: () => void;
  showReexchange: boolean;
  expirySecondsLeft: number | null;
}

const TokensTab: React.FC<TokensTabProps> = ({
  tokens, loadingToken, loadingUserinfo, userInfo, onFetchUserInfo, onCopy, onToast, onRefresh, onReexchange, showReexchange, expirySecondsLeft,
}) => (
  <Card>
    <CardHeader>
      <CardTitle className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Token Display
        </div>
        <div className="flex items-center gap-2">
          {tokens?.refresh_token && (
            <Button size="sm" variant="outline" onClick={onRefresh} disabled={loadingToken} aria-label="Refresh tokens">
              {loadingToken ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
              Refresh
            </Button>
          )}
          {showReexchange && (
            <Button size="sm" variant="outline" onClick={onReexchange} disabled={loadingToken}>
              {loadingToken ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
              Re-exchange Code
            </Button>
          )}
        </div>
      </CardTitle>
    </CardHeader>
    <CardContent>
      {loadingToken && !tokens ? (
        <div className="space-y-3">
          <Skeleton className="h-4 w-1/3" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-4 w-1/3" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : tokens ? (
        <div className="space-y-6">
          {expirySecondsLeft !== null && (
            <Alert>
              <Clock className="h-4 w-4" />
              <AlertDescription>
                Access token expires in <span className="font-mono font-semibold">{expirySecondsLeft}s</span>
                {expirySecondsLeft <= 0 && ' — expired'}
              </AlertDescription>
            </Alert>
          )}
          <div className="space-y-4">
            {Object.entries(tokens).map(([key, value]) => {
              const isSecret = SECRET_TOKEN_FIELDS.has(key);
              return (
                <div key={key} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label className="text-sm font-medium capitalize flex items-center gap-2">
                      {key.replace(/_/g, ' ')}
                      {isSecret && <Lock className="h-3 w-3 text-muted-foreground" aria-label="sensitive" />}
                    </Label>
                  </div>
                  {isSecret && isJwtLike(value) ? (
                    (() => {
                      const decoded = decodeJwt(value as string);
                      return (
                        <>
                          <MaskedValue value={value as string} onCopy={(ok) => (ok ? onToast({ title: 'Copied' }) : onToast({ title: 'Copy failed', variant: 'destructive' }))} />
                          {decoded && <JsonHighlight value={{ header: decoded.header, payload: decoded.payload, signature: decoded.signature }} />}
                        </>
                      );
                    })()
                  ) : isSecret ? (
                    <MaskedValue value={String(value)} onCopy={(ok) => (ok ? onToast({ title: 'Copied' }) : onToast({ title: 'Copy failed', variant: 'destructive' }))} />
                  ) : (
                    <div className="flex items-center gap-2">
                      <code className="text-xs bg-code-bg p-2 rounded border border-code-border flex-1 break-all code-block font-mono">{String(value)}</code>
                      <Button size="sm" variant="outline" aria-label={`Copy ${key}`} onClick={() => onCopy(String(value))}><Copy className="h-3 w-3" /></Button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div className="border-t border-border pt-6">
            <div className="flex items-center justify-between mb-4">
              <Label className="text-sm font-medium">UserInfo Endpoint</Label>
              <Button onClick={onFetchUserInfo} disabled={loadingUserinfo || !tokens.access_token} size="sm">
                {loadingUserinfo ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Globe className="h-4 w-4 mr-2" />}
                Fetch UserInfo
              </Button>
            </div>
            {loadingUserinfo && <Skeleton className="h-24 w-full" />}
            {!loadingUserinfo && userInfo ? (
              <JsonHighlight value={userInfo} />
            ) : (
              !loadingUserinfo && <div className="text-sm text-muted-foreground">Click "Fetch UserInfo" to query the userinfo endpoint with the access token.</div>
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
);

export default TokensTab;
