import React from 'react';
import { CheckCircle } from 'lucide-react';
import type { FlowStep } from './types';

const STEPS: { key: FlowStep; label: string }[] = [
  { key: 'discover', label: 'Discover' },
  { key: 'configure', label: 'Configure' },
  { key: 'authenticate', label: 'Authenticate' },
  { key: 'tokens', label: 'Tokens' },
];

const FlowStepper: React.FC<{ current: FlowStep }> = ({ current }) => {
  const stepIndex = STEPS.findIndex((s) => s.key === current);
  return (
    <div className="flex items-center justify-between max-w-3xl mx-auto px-2" aria-label="Flow progress">
      {STEPS.map((s, i) => {
        const done = i < stepIndex;
        const active = i === stepIndex;
        return (
          <React.Fragment key={s.key}>
            <div className="flex flex-col items-center gap-1 flex-1">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold border transition-all ${
                  done
                    ? 'bg-success/20 border-success text-success'
                    : active
                    ? 'bg-primary/20 border-primary text-primary shadow-glow-primary'
                    : 'bg-muted border-border text-muted-foreground'
                }`}
              >
                {done ? <CheckCircle className="w-4 h-4" /> : i + 1}
              </div>
              <span className={`text-[10px] uppercase tracking-wide ${active ? 'text-foreground' : 'text-muted-foreground'}`}>
                {s.label}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div className={`h-px flex-1 mx-1 ${i < stepIndex ? 'bg-success/50' : 'bg-border'}`} />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
};

export default FlowStepper;
