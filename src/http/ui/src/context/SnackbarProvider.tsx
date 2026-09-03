// src/http/ui/src/context/SnackbarContext.tsx
import { createContext, use, useEffect, useMemo, useRef, useState, useCallback, ReactNode } from "react";
import { Snackbar } from "@mui/material";
import { B4Alert } from "@b4.elements";

type Severity = "error" | "warning" | "info" | "success";

interface SnackbarItem {
  key: number;
  message: string;
  severity: Severity;
}

interface SnackbarContextType {
  showSnackbar: (message: string, severity?: Severity) => void;
  showError: (message: string) => void;
  showSuccess: (message: string) => void;
}

const SnackbarContext = createContext<SnackbarContextType | null>(null);

export function SnackbarProvider({
  children,
}: Readonly<{ children: ReactNode }>) {
  const [queue, setQueue] = useState<SnackbarItem[]>([]);
  const [open, setOpen] = useState(false);
  const keyRef = useRef(0);

  const current = queue[0];

  const showSnackbar = useCallback(
    (message: string, severity: Severity = "info") => {
      keyRef.current += 1;
      setQueue((q) => [...q, { key: keyRef.current, message, severity }]);
    },
    [],
  );

  const showError = useCallback(
    (message: string) => showSnackbar(message, "error"),
    [showSnackbar],
  );
  const showSuccess = useCallback(
    (message: string) => showSnackbar(message, "success"),
    [showSnackbar],
  );

  useEffect(() => {
    if (current) setOpen(true);
  }, [current]);

  const handleClose = useCallback(
    (_event?: unknown, reason?: string) => {
      if (reason === "clickaway") return;
      setOpen(false);
    },
    [],
  );

  const handleExited = useCallback(() => {
    setQueue((q) => q.slice(1));
  }, []);

  return (
    <SnackbarContext value={useMemo(() => ({ showSnackbar, showError, showSuccess }), [showSnackbar, showError, showSuccess])}>
      {children}
      <Snackbar
        key={current?.key}
        open={open && !!current}
        autoHideDuration={current?.severity === "error" ? 8000 : 4000}
        onClose={handleClose}
        slotProps={{ transition: { onExited: handleExited } }}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
      >
        <B4Alert noWrapper onClose={handleClose} severity={current?.severity ?? "info"}>
          {current?.message ?? ""}
        </B4Alert>
      </Snackbar>
    </SnackbarContext>
  );
}

export function useSnackbar(): SnackbarContextType {
  const context = use(SnackbarContext);
  if (!context) {
    throw new Error("useSnackbar must be used within SnackbarProvider");
  }
  return context;
}
