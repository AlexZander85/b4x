import { Container, Stack } from "@mui/material";
import { AdBlockPanel } from "./AdBlockPanel";

export function AdBlockPage() {
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
        <AdBlockPanel />
      </Stack>
    </Container>
  );
}

export default AdBlockPage;
