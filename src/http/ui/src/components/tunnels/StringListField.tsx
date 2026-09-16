import { useState } from "react";
import { Box, Chip, IconButton, Stack, TextField } from "@mui/material";
import { AddIcon, CloseIcon } from "@b4.icons";
import { colors } from "@design";

interface StringListFieldProps {
  label: string;
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
  helperText?: string;
}

// Compact string-list editor (chips + add row) for tunnel config fields
// like sni_pool / alpn / bridge lines.
export function StringListField({
  label,
  values,
  onChange,
  placeholder,
  helperText,
}: StringListFieldProps) {
  const [draft, setDraft] = useState("");

  const addDraft = () => {
    const v = draft.trim();
    if (!v || values.includes(v)) {
      setDraft("");
      return;
    }
    onChange([...values, v]);
    setDraft("");
  };

  return (
    <Box>
      <Stack direction="row" spacing={1} alignItems="flex-start">
        <TextField
          fullWidth
          size="small"
          label={label}
          placeholder={placeholder}
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              addDraft();
            }
          }}
          helperText={helperText}
        />
        <IconButton size="small" onClick={addDraft} disabled={!draft.trim()}>
          <AddIcon fontSize="small" />
        </IconButton>
      </Stack>
      {values.length > 0 && (
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 1 }}>
          {values.map((v) => (
            <Chip
              key={v}
              size="small"
              label={v}
              onDelete={() => {
                onChange(values.filter((x) => x !== v));
              }}
              sx={{
                maxWidth: 320,
                fontFamily: "monospace",
                fontSize: 12,
                bgcolor: colors.background.default,
              }}
            />
          ))}
        </Box>
      )}
    </Box>
  );
}
