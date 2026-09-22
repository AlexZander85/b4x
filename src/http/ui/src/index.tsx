import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./i18n";
import App from "./App";
import { AuthProvider } from "./context/AuthProvider";
import { WebSocketProvider } from "./context/B4WsProvider";
import { AiStatusProvider } from "./context/AiStatusProvider";

// The classifier page (components/classifier/*) uses @tanstack/react-query
// (useQuery/useMutation); without a provider React Query throws
// "No QueryClient set" and the route renders a blank screen.
const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } },
});

const root = createRoot(document.getElementById("root")!);
root.render(
  <BrowserRouter>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <WebSocketProvider>
          <AiStatusProvider>
            <App />
          </AiStatusProvider>
        </WebSocketProvider>
      </AuthProvider>
    </QueryClientProvider>
  </BrowserRouter>,
);
