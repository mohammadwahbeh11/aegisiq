import { Navigate, Route, Routes } from "react-router-dom";

import Layout from "./components/Layout";
import { useAuth } from "./context/AuthContext";
import { LiveProvider } from "./context/LiveContext";
import AlertDetail from "./pages/AlertDetail";
import Alerts from "./pages/Alerts";
import Analysis from "./pages/Analysis";          // v2.1 premium
import Audit from "./pages/Audit";                // v2.0
import Dashboard from "./pages/Dashboard";
import Endpoints from "./pages/Endpoints";
import Login from "./pages/Login";
import Logs from "./pages/Logs";
import Response from "./pages/Response";
import Retention from "./pages/Retention";
import Rules from "./pages/Rules";
import Security from "./pages/Security";          // v2.3 MFA
import Simulation from "./pages/Simulation";

/**
 * The LiveProvider wraps the whole authenticated area rather than any
 * single page, so the WebSocket survives navigation: moving from the
 * dashboard to the alert queue must not drop and re-open the stream, and
 * the alert toast has to appear no matter which page is open.
 */
function ProtectedArea() {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return (
    <LiveProvider>
      <Layout />
    </LiveProvider>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<ProtectedArea />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/alerts/:alertId" element={<AlertDetail />} />
        <Route path="/logs" element={<Logs />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="/endpoints" element={<Endpoints />} />
        <Route path="/response" element={<Response />} />
        <Route path="/retention" element={<Retention />} />
        <Route path="/audit" element={<Audit />} />       {/* v2.0 */}
        <Route path="/analysis" element={<Analysis />} /> {/* v2.1 premium */}
        <Route path="/security" element={<Security />} /> {/* v2.3 MFA */}
        <Route path="/simulation" element={<Simulation />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
