import { Container, Stack } from "@mui/material";
import { TunnelsPane } from "./TunnelsPane";

export function TunnelsPage() {
  return (
    <Container
      maxWidth={false}
      sx={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        overflow: "auto",
        py: 3,
      }}
    >
      <Stack spacing={3}>
        <TunnelsPane />
      </Stack>
    </Container>
  );
}
