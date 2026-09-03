import { Box } from "@mui/material";
import { colors } from "@design";

interface B4MiniBarsProps {
  data: number[];
  color?: string;
  height?: number;
  sx?: object;
}

export const B4MiniBars = ({
  data,
  color = colors.secondary,
  height = 24,
  sx,
}: B4MiniBarsProps) => {
  const max = Math.max(...data, 1);
  return (
    <Box
      sx={{
        display: "flex",
        alignItems: "flex-end",
        gap: "1px",
        height,
        flex: 1,
        minWidth: 0,
        ...sx,
      }}
    >
      {data.map((v, i) => (
        <Box
          key={i}
          component="span"
          sx={{
            flex: 1,
            height: Math.max(2, (v / max) * height),
            backgroundColor: color,
            borderRadius: "1px 1px 0 0",
          }}
        />
      ))}
    </Box>
  );
};
