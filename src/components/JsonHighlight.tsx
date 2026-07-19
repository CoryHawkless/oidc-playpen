import React from 'react';

/** Lightweight JSON syntax highlighter styled with the existing --json-* CSS vars. */
const JsonHighlight: React.FC<{ value: unknown; className?: string }> = ({ value, className }) => {
  let pretty: string;
  try {
    const parsed = typeof value === 'string' ? JSON.parse(value) : value;
    pretty = JSON.stringify(parsed, null, 2);
  } catch {
    pretty = typeof value === 'string' ? value : String(value ?? '');
  }

  // Escape HTML first to avoid injection through token content.
  const escaped = pretty
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Highlight in an order that won't double-replace: strings (incl. keys), numbers, booleans/null.
  const html = escaped.replace(
    /("(?:\\.|[^"\\])*"\s*:)|("(?:\\.|[^"\\])*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(\b(?:true|false|null)\b)/g,
    (match, key, str, num, bool) => {
      if (key) return `<span style="color: hsl(var(--json-key))">${key}</span>`;
      if (str) return `<span style="color: hsl(var(--json-string))">${str}</span>`;
      if (num) return `<span style="color: hsl(var(--json-number))">${num}</span>`;
      if (bool) return `<span style="color: hsl(var(--json-boolean))">${bool}</span>`;
      return match;
    }
  );

  return (
    <pre
      className={`text-xs bg-code-bg p-3 rounded border border-code-border overflow-x-auto code-block ${className ?? ''}`}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
};

export default JsonHighlight;
