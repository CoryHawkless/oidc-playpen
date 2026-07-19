import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { Globe, Copy, CheckCircle, Loader2 } from 'lucide-react';
import type { DiscoveryDocument, OIDCConfig } from './types';

interface SetupTabProps {
  config: OIDCConfig;
  setConfig: React.Dispatch<React.SetStateAction<OIDCConfig>>;
  discovery: DiscoveryDocument | null;
  loadingDiscovery: boolean;
  onFetchDiscovery: () => void;
  onCopy: (text: string) => void;
}

const SetupTab: React.FC<SetupTabProps> = ({ config, setConfig, discovery, loadingDiscovery, onFetchDiscovery, onCopy }) => (
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
            onChange={(e) => setConfig((prev) => ({ ...prev, baseUrl: e.target.value }))}
            onKeyDown={(e) => { if (e.key === 'Enter' && !loadingDiscovery) { e.preventDefault(); onFetchDiscovery(); } }}
            className="flex-1"
          />
          <Button onClick={onFetchDiscovery} disabled={loadingDiscovery} className="min-w-[120px] btn-glow bg-primary hover:bg-primary/90">
            {loadingDiscovery ? <Loader2 className="h-4 w-4 animate-spin" /> : (<><Globe className="h-4 w-4 mr-2" />Fetch Config</>)}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">Press Enter in the URL field to fetch.</p>
      </div>

      {loadingDiscovery && (
        <div className="space-y-3">
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
          <Skeleton className="h-20 w-full" />
        </div>
      )}

      {!loadingDiscovery && discovery && (
        <div className="space-y-4">
          <Alert>
            <CheckCircle className="h-4 w-4" />
            <AlertDescription>Discovery document loaded from {discovery.issuer}</AlertDescription>
          </Alert>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <Label className="text-sm font-medium">Authorization Endpoint</Label>
              <div className="flex items-center gap-2 mt-1">
                <code className="text-xs bg-code-bg p-2 rounded border border-code-border flex-1 truncate code-block">{discovery.authorization_endpoint}</code>
                <Button size="sm" variant="outline" aria-label="Copy authorization endpoint" onClick={() => onCopy(discovery.authorization_endpoint)}><Copy className="h-3 w-3" /></Button>
              </div>
            </div>
            <div>
              <Label className="text-sm font-medium">Token Endpoint</Label>
              <div className="flex items-center gap-2 mt-1">
                <code className="text-xs bg-code-bg p-2 rounded border border-code-border flex-1 truncate code-block">{discovery.token_endpoint}</code>
                <Button size="sm" variant="outline" aria-label="Copy token endpoint" onClick={() => onCopy(discovery.token_endpoint)}><Copy className="h-3 w-3" /></Button>
              </div>
            </div>
          </div>
          {discovery.scopes_supported && (
            <div>
              <Label className="text-sm font-medium">Supported Scopes</Label>
              <div className="flex flex-wrap gap-1 mt-2">
                {discovery.scopes_supported.map((scope) => (
                  <Badge key={scope} variant="secondary" className="text-xs badge-glow hover:bg-secondary/80">{scope}</Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="space-y-4 pt-6 border-t border-border">
        <div className="flex items-center space-x-2">
          <Switch
            id="useManualConfig"
            checked={config.useManualConfig}
            onCheckedChange={(v) => setConfig((prev) => ({ ...prev, useManualConfig: v }))}
          />
          <Label htmlFor="useManualConfig" className="text-sm font-medium cursor-pointer">
            Use Manual Configuration (bypass discovery / CORS)
          </Label>
        </div>

        {config.useManualConfig && (
          <div className="space-y-4 bg-muted/50 p-4 rounded-lg">
            <h4 className="font-semibold text-sm">Manual OIDC Endpoints</h4>
            <div className="grid grid-cols-1 gap-4">
              <div className="space-y-2">
                <Label htmlFor="issuer">Issuer</Label>
                <Input id="issuer" placeholder="https://provider.example.com/" value={config.manualConfig.issuer} onChange={(e) => setConfig((prev) => ({ ...prev, manualConfig: { ...prev.manualConfig, issuer: e.target.value } }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="authEndpoint">Authorization Endpoint</Label>
                <Input id="authEndpoint" placeholder="https://provider.example.com/oauth/authorize" value={config.manualConfig.authorizationEndpoint} onChange={(e) => setConfig((prev) => ({ ...prev, manualConfig: { ...prev.manualConfig, authorizationEndpoint: e.target.value } }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="tokenEndpoint">Token Endpoint</Label>
                <Input id="tokenEndpoint" placeholder="https://provider.example.com/oauth/token" value={config.manualConfig.tokenEndpoint} onChange={(e) => setConfig((prev) => ({ ...prev, manualConfig: { ...prev.manualConfig, tokenEndpoint: e.target.value } }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="userinfoEndpoint">Userinfo Endpoint</Label>
                <Input id="userinfoEndpoint" placeholder="https://provider.example.com/oauth/userinfo" value={config.manualConfig.userinfoEndpoint} onChange={(e) => setConfig((prev) => ({ ...prev, manualConfig: { ...prev.manualConfig, userinfoEndpoint: e.target.value } }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="jwksUri">JWKS URI</Label>
                <Input id="jwksUri" placeholder="https://provider.example.com/.well-known/jwks.json" value={config.manualConfig.jwksUri} onChange={(e) => setConfig((prev) => ({ ...prev, manualConfig: { ...prev.manualConfig, jwksUri: e.target.value } }))} />
              </div>
            </div>
          </div>
        )}
      </div>
    </CardContent>
  </Card>
);

export default SetupTab;
