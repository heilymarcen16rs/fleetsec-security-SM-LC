import { buildApp } from './app.js';
import { config } from './config.js';

buildApp().then((app) => {
  app.listen(config.port, () => {
    // eslint-disable-next-line no-console
    console.log(`FleetSec API listening on :${config.port} (env=${config.env}, LAB_MODE=${process.env.LAB_MODE !== 'false'})`);
  });
});
