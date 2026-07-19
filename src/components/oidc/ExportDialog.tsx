import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from '@/components/ui/dialog';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Download, Lock, Unlock } from 'lucide-react';

interface ExportDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onExport: (includeSecrets: boolean) => void;
}

const ExportDialog: React.FC<ExportDialogProps> = ({ open, onOpenChange, onExport }) => {
  const [includeSecrets, setIncludeSecrets] = useState(false);
  useEffect(() => { if (!open) setIncludeSecrets(false); }, [open]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Download className="h-4 w-4" /> Export session</DialogTitle>
          <DialogDescription>
            Export the current configuration, discovery document, tokens, userinfo, and request logs as a JSON file.
          </DialogDescription>
        </DialogHeader>
        <div className="flex items-start gap-3 py-4">
          <Checkbox id="includeSecrets" checked={includeSecrets} onCheckedChange={(v) => setIncludeSecrets(Boolean(v))} className="mt-1" />
          <div>
            <Label htmlFor="includeSecrets" className="text-sm font-medium cursor-pointer flex items-center gap-2">
              {includeSecrets ? <Unlock className="h-3 w-3" /> : <Lock className="h-3 w-3" />}
              Include secrets
            </Label>
            <p className="text-xs text-muted-foreground mt-1">
              When unchecked: client secret, token values, and Authorization headers are redacted. When checked: full values are written to the file — handle with care.
            </p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => onExport(includeSecrets)} className="bg-primary hover:bg-primary/90">
            {includeSecrets ? <Unlock className="h-4 w-4 mr-2" /> : <Lock className="h-4 w-4 mr-2" />}
            Export {includeSecrets ? 'with secrets' : '(redacted)'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default ExportDialog;
