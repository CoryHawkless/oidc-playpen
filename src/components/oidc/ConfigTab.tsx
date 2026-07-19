import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Key, Play, Copy, Globe, XCircle, CheckCircle } from 'lucide-react';
import type { OIDCConfig } from './types';

interface ConfigTabProps {
  config: OIDCConfig;
  setConfig: React.Dispatch<React.SetStateAction<OIDCConfig>>;
  showSecret: boolean;
  setShowSecret: (v: boolean) => void;
  authUrl: string;
  onGenerateAuthUrl: () => void;
  onBeginFlow: () => void;
  canBeginFlow: boolean;
  onCopy: (text: string) => void;
}

const ConfigTab: React.FC<ConfigTabProps> = ({
  config, setConfig, showSecret, setShowSecret, authUrl, onGenerateAuthUrl, onBeginFlow, canBeginFlow, onCopy,
}) => (
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
          <Input id="clientId" placeholder="your-client-id" value={config.clientId} onChange={(e) => setConfig((prev) => ({ ...prev, clientId: e.target.value }))} />
        </div>
        <div className="space-y-2">
          <Label htmlFor="clientSecret">Client Secret (Optional)</Label>
          <div className="relative">
            <Input id="clientSecret" type={showSecret ? 'text' : 'password'} placeholder="your-client-secret" value={config.clientSecret} onChange={(e) => setConfig((prev) => ({ ...prev, clientSecret: e.target.value }))} className="pr-10" />
            <Button type="button" variant="ghost" size="sm" className="absolute right-0 top-0 h-full px-3" aria-label={showSecret ? 'Hide secret' : 'Show secret'} onClick={() => setShowSecret(!showSecret)}>
              {showSecret ? <XCircle className="h-4 w-4" /> : <CheckCircle className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="flowType">Flow Type</Label>
        <Select value={config.flowType} onValueChange={(value: OIDCConfig['flowType']) => setConfig((prev) => ({ ...prev, flowType: value }))}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="authorization_code">Authorization Code + PKCE (Recommended)</SelectItem>
            <SelectItem value="implicit">Implicit Flow (Deprecated - RFC 9700)</SelectItem>
            <SelectItem value="hybrid">Hybrid Flow</SelectItem>
            <SelectItem value="client_credentials">Client Credentials (no user redirect)</SelectItem>
          </SelectContent>
        </Select>
        {config.flowType === 'implicit' && (
          <p className="text-xs text-destructive mt-1">⚠️ Implicit flow is deprecated per RFC 9700. Use Authorization Code + PKCE instead.</p>
        )}
        {config.flowType === 'client_credentials' && (
          <p className="text-xs text-muted-foreground mt-1">Client Credentials posts directly to the token endpoint — no redirect or popup is used.</p>
        )}
      </div>

      {config.flowType !== 'client_credentials' && (
        <div className="space-y-2">
          <Label htmlFor="redirectUri">Redirect URI</Label>
          <Input id="redirectUri" value={config.redirectUri} onChange={(e) => setConfig((prev) => ({ ...prev, redirectUri: e.target.value }))} />
        </div>
      )}

      <div className="space-y-2">
        <Label htmlFor="scopes">Scopes (space-separated)</Label>
        <Input id="scopes" placeholder="openid profile email" value={config.scopes.join(' ')} onChange={(e) => setConfig((prev) => ({ ...prev, scopes: e.target.value.split(' ').filter(Boolean) }))} />
      </div>

      {authUrl && config.flowType !== 'client_credentials' && (
        <div className="space-y-2">
          <Label>Generated Authorization URL</Label>
          <div className="flex gap-2">
            <Textarea value={authUrl} readOnly className="font-mono text-xs" rows={3} />
            <div className="flex flex-col gap-2">
              <Button size="sm" variant="outline" aria-label="Copy authorization URL" onClick={() => onCopy(authUrl)}><Copy className="h-3 w-3" /></Button>
              <Button size="sm" variant="outline" aria-label="Open authorization URL" onClick={() => window.open(authUrl, '_blank')}><Globe className="h-3 w-3" /></Button>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-col sm:flex-row gap-2 pt-4">
        {config.flowType !== 'client_credentials' && (
          <Button onClick={onGenerateAuthUrl} variant="outline" className="hover:border-primary/50 hover:bg-primary/5 transition-all duration-200">Generate URL</Button>
        )}
        <Button onClick={onBeginFlow} disabled={!canBeginFlow} className="flex-1 btn-glow bg-primary hover:bg-primary/90">
          <Play className="h-4 w-4 mr-2" />
          {config.flowType === 'client_credentials' ? 'Request Token' : 'Begin Flow'}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">Tip: Ctrl/Cmd + Enter starts the flow.</p>
    </CardContent>
  </Card>
);

export default ConfigTab;
