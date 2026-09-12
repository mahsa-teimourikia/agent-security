import React from "react";
import ReactDOM from "react-dom/client";

import App from "./page";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Missing #root mount point");
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
