import { Container, Stack } from "@mui/material";
import { DnsPanel } from "./DnsPanel";

export function DnsPage() {
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
        <DnsPanel />
      </Stack>
    </Container>
  );
}

export default DnsPage;
