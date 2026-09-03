import { useState, useCallback } from "react";

interface UpdateResponse {
  success: boolean;
  message: string;
  service_manager: string;
  update_command?: string;
}

export const useSystemUpdate = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const performUpdate = useCallback(
    async (version?: string): Promise<UpdateResponse | null> => {
      setLoading(true);
      setError(null);

      try {
        const response = await fetch("/api/system/update", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ version }),
        });

        const rawData: unknown = await response.json();

        function isUpdateResponse(obj: unknown): obj is UpdateResponse {
          return (
            typeof obj === "object" &&
            obj !== null &&
            "success" in obj &&
            typeof obj.success === "boolean" &&
            "message" in obj &&
            typeof (obj as { message: unknown }).message === "string" &&
            "service_manager" in obj &&
            typeof (obj as { service_manager: unknown }).service_manager ===
              "string"
          );
        }

        const data: UpdateResponse = isUpdateResponse(rawData)
          ? rawData
          : {
              success: false,
              message: "Invalid response format",
              service_manager: "",
            };

        if (!response.ok) {
          const errorMessage = data.message || "Failed to initiate update";
          setError(errorMessage);
          setLoading(false);
          return data;
        }

        return data;
      } catch (err) {
        if (err instanceof Error) {
          console.error("Update error:", err.message);
          setError(`Update failed: ${err.message}`);
        } else {
          console.error("Unknown error during update:", err);
          setError("An unknown error occurred during update");
        }
        setLoading(false);
        return null;
      }
    },
    [],
  );

  const waitForReconnection = useCallback(
    async (maxAttempts: number = 60): Promise<boolean> => {
      let attempts = 0;

      while (attempts < maxAttempts) {
        await new Promise((resolve) => setTimeout(resolve, 3000));
        attempts++;

        try {
          const response = await fetch("/api/version", {
            method: "GET",
            cache: "no-cache",
          });

          if (response.ok) {
            setLoading(false);
            return true;
          }
        } catch {
          // Service not yet available (network error)
        }
      }

      setLoading(false);
      setError("Update did not complete within expected time");
      return false;
    },
    [],
  );

  return {
    performUpdate,
    waitForReconnection,
    loading,
    error,
  };
};
