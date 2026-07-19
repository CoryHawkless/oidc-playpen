import { useLocation } from "react-router-dom";
import { useEffect } from "react";
import { Shield } from "lucide-react";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error(
      "404 Error: User attempted to access non-existent route:",
      location.pathname
    );
  }, [location.pathname]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-background text-foreground p-6">
      <div className="text-center space-y-4 max-w-md">
        <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-gradient-to-br from-primary to-primary-glow shadow-glow-primary mx-auto">
          <Shield className="w-6 h-6 text-primary-foreground" />
        </div>
        <h1 className="text-6xl font-mono font-bold tracking-tight">404</h1>
        <p className="text-xl text-muted-foreground">Page not found</p>
        <p className="text-sm text-muted-foreground">
          The route <code className="text-xs bg-code-bg p-1 rounded border border-code-border font-mono break-all">{location.pathname}</code> doesn't exist.
        </p>
        <a
          href="/"
          className="inline-flex items-center gap-2 text-primary hover:text-primary-glow underline-offset-4 hover:underline"
        >
          Return to OIDC Playpen
        </a>
      </div>
    </div>
  );
};

export default NotFound;
