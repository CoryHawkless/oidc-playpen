import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Clock, Download, Trash2 } from 'lucide-react';
import JsonHighlight from '@/components/JsonHighlight';
import { redactHeaders, formatTime } from '@/lib/oidc-utils';
import type { RequestLog } from './types';

interface LogsTabProps {
  logs: RequestLog[];
  onClear: () => void;
  onExport: () => void;
}

const LogsTab: React.FC<LogsTabProps> = ({ logs, onClear, onExport }) => (
  <Card>
    <CardHeader>
      <CardTitle className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Clock className="h-5 w-5" />
          Logs
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={onClear} variant="outline" size="sm" disabled={logs.length === 0} aria-label="Clear logs">
            <Trash2 className="h-4 w-4 mr-2" />
            Clear
          </Button>
          <Button onClick={onExport} variant="outline" size="sm" aria-label="Export session">
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
        </div>
      </CardTitle>
    </CardHeader>
    <CardContent>
      {logs.length > 0 ? (
        <div className="space-y-4">
          {logs.map((log) => {
            const isRedirect = log.method === 'REDIRECT';
            const failed = log.response?.status !== undefined && (log.response.status === 0 || log.response.status >= 400);
            return (
              <div
                key={log.id}
                className={`border rounded-lg p-4 space-y-2 transition-all duration-200 hover:-translate-y-0.5 ${
                  isRedirect ? 'log-warning border-warning/30 bg-warning/5'
                    : failed ? 'log-error border-destructive/30 bg-destructive/5'
                    : 'log-success border-success/30 bg-success/5'
                }`}
              >
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2 min-w-0">
                    <Badge variant={failed ? 'destructive' : 'default'} className={`badge-glow ${isRedirect ? 'bg-warning text-warning-foreground hover:bg-warning/90' : ''}`}>
                      {log.method}
                    </Badge>
                    <span className="font-mono text-sm truncate max-w-[60vw] md:max-w-md">{log.url}</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    {log.response?.status !== undefined && (
                      <Badge variant={failed ? 'destructive' : 'default'}>{log.response.status}</Badge>
                    )}
                    {log.response?.duration !== undefined && log.response.duration > 0 && (<span>{log.response.duration}ms</span>)}
                    <span>{formatTime(log.timestamp)}</span>
                  </div>
                </div>

                <details className="text-sm">
                  <summary className="cursor-pointer text-muted-foreground">Request URL</summary>
                  <pre className="mt-2 bg-code-bg p-3 rounded border border-code-border overflow-x-auto text-xs break-all whitespace-pre-wrap">{log.url}</pre>
                </details>

                {Object.keys(log.headers).length > 0 && (
                  <details className="text-sm">
                    <summary className="cursor-pointer text-muted-foreground">Request Headers <span className="text-xs">(secrets redacted in view)</span></summary>
                    <JsonHighlight value={redactHeaders(log.headers)} />
                  </details>
                )}

                {log.body && (
                  <details className="text-sm">
                    <summary className="cursor-pointer text-muted-foreground">Request Payload</summary>
                    <JsonHighlight value={log.body} />
                  </details>
                )}

                {log.response && Object.keys(log.response.headers).length > 0 && (
                  <details className="text-sm">
                    <summary className="cursor-pointer text-muted-foreground">Response Headers <span className="text-xs">(secrets redacted in view)</span></summary>
                    <JsonHighlight value={redactHeaders(log.response.headers)} />
                  </details>
                )}

                {log.response && (
                  <details className="text-sm">
                    <summary className="cursor-pointer text-muted-foreground">{isRedirect ? 'Callback Data' : 'Response Body'}</summary>
                    <JsonHighlight value={log.response.body} />
                  </details>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="text-center py-8 text-muted-foreground">No requests logged yet. Interact with the OIDC provider to see request logs here.</div>
      )}
    </CardContent>
  </Card>
);

export default LogsTab;
