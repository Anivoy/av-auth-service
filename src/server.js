import app from "./app.js";
import { serverConfig } from "./config/env.js";

app.listen(PORT, () => {
  console.log(`Server running on PORT: ${serverConfig.PORT}`);
});
