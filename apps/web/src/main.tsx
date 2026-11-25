import React from "react";
import ReactDOM from "react-dom/client";
import { Landing } from "./pages/Landing";
import { Dashboard } from "./pages/Dashboard";
import "./styles.css";

function App() {
  const path = window.location.pathname;
  return path === "/app" ? <Dashboard /> : <Landing />;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
