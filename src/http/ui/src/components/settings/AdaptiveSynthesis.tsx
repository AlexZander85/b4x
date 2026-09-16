import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Box, Button, DialogContent, DialogContentText } from "@mui/material";

import { DiscoveryIcon } from "@b4.icons";
import { B4Alert, B4Dialog, B4Section, B4Switch } from "@b4.elements";
import { B4Config } from "@models/config";
import { SettingsPropHandlerType } from "@models/settings";

interface AdaptiveSynthesisSettingsProps {
  config: B4Config;
  onChange: (field: string, value: SettingsPropHandlerType) => void;
}

export const AdaptiveSynthesisSettings = ({
  config,
  onChange,
}: AdaptiveSynthesisSettingsProps) => {
  const { t } = useTranslation();
  const [showEnableConfirm, setShowEnableConfirm] = useState(false);
  const enabled =
    config.automation?.adaptive_strategy_synthesis?.enabled ?? false;

  const handleToggle = (checked: boolean) => {
    if (!checked) {
      onChange("automation.adaptive_strategy_synthesis.enabled", false);
      return;
    }
    if (!enabled) {
      setShowEnableConfirm(true);
    }
  };

  const confirmEnable = () => {
    onChange("automation.adaptive_strategy_synthesis.enabled", true);
    setShowEnableConfirm(false);
  };

  return (
    <>
      <B4Section
        title={t("afs.settings.title")}
        description={t("afs.settings.description")}
        icon={<DiscoveryIcon />}
      >
        <B4Switch
          label={t("afs.settings.adaptiveSynthesis")}
          checked={enabled}
          onChange={handleToggle}
          description={t("afs.settings.adaptiveSynthesisDesc")}
        />
        {enabled && (
          <B4Alert severity="info" sx={{ mt: 2 }}>
            {t("afs.settings.enabledNotice")}
          </B4Alert>
        )}
      </B4Section>

      <B4Dialog
        title={t("afs.settings.confirmTitle")}
        open={showEnableConfirm}
        onClose={() => setShowEnableConfirm(false)}
        actions={
          <>
            <Button onClick={() => setShowEnableConfirm(false)}>
              {t("core.cancel")}
            </Button>
            <Box sx={{ flex: 1 }} />
            <Button onClick={confirmEnable} variant="contained">
              {t("afs.settings.confirmEnable")}
            </Button>
          </>
        }
      >
        <DialogContent>
          <DialogContentText>
            {t("afs.settings.confirmBody")}
          </DialogContentText>
        </DialogContent>
      </B4Dialog>
    </>
  );
};
