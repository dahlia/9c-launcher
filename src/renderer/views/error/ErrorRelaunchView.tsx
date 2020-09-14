import React, { useCallback, useEffect } from "react";
import { remote } from "electron";
import mixpanel from "mixpanel-browser";
import errorViewStyle from "./ErrorView.style";
import { Button, Container, Typography } from "@material-ui/core";
import * as Sentry from "@sentry/electron";

import { useLocale } from "../../i18n";

const ErrorRelaunchView = () => {
  const classes = errorViewStyle();

  const { locale } = useLocale("errorRelaunch");

  const steps = locale("steps");
  if (typeof steps === "string")
    throw Error("errorRelaunch.steps is not array in src/i18n/index.json");

  const handleRelaunch = useCallback(() => {
    remote.app.relaunch();
    remote.app.exit();
  }, []);

  useEffect(() => {
    mixpanel.track("Launcher/ErrorRelaunch");
    Sentry.captureException(new Error("Reinstall required."));
  }, []);
  return (
    <Container className={classes.root}>
      <Typography variant="h1" gutterBottom className={classes.title}>
        {locale("Something went wrong.")}
      </Typography>
      <Typography variant="subtitle1">
        {locale("Please follow the steps below.")}
      </Typography>
      <ol>
        {steps.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ol>
      <Button
        className={classes.button}
        color="primary"
        variant="contained"
        fullWidth
        onClick={handleRelaunch}
      >
        {locale("Relaunch")}
      </Button>
    </Container>
  );
};

export default ErrorRelaunchView;
