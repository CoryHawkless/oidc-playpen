import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Copy, Eye, EyeOff } from 'lucide-react';
import { copyText } from '@/lib/oidc-utils';

interface MaskedValueProps {
  /** The full secret value. */
  value: string;
  /** Called when the copy button is pressed. */
  onCopy?: (ok: boolean) => void;
  /** Number of characters to reveal at the head/tail when masked. */
  revealEdges?: number;
  className?: string;
}

/** Displays a sensitive value masked by default, with reveal + copy controls. */
const MaskedValue: React.FC<MaskedValueProps> = ({ value, onCopy, revealEdges = 6, className }) => {
  const [revealed, setRevealed] = useState(false);

  const masked = React.useMemo(() => {
    if (revealed || value.length <= revealEdges * 2) return value;
    return `${value.slice(0, revealEdges)}…${value.slice(-revealEdges)}`;
  }, [revealed, value, revealEdges]);

  const handleCopy = async () => {
    const ok = await copyText(value);
    onCopy?.(ok);
  };

  return (
    <div className={`flex items-center gap-2 ${className ?? ''}`}>
      <code className="text-xs bg-code-bg p-2 rounded border border-code-border flex-1 break-all code-block font-mono">
        {masked}
      </code>
      <Button
        type="button"
        size="sm"
        variant="outline"
        aria-label={revealed ? 'Hide value' : 'Reveal value'}
        onClick={() => setRevealed((v) => !v)}
      >
        {revealed ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
      </Button>
      <Button
        type="button"
        size="sm"
        variant="outline"
        aria-label="Copy value"
        onClick={handleCopy}
      >
        <Copy className="h-3 w-3" />
      </Button>
    </div>
  );
};

export default MaskedValue;
