import { Link, Route, Routes } from "react-router-dom";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { AlertsPage } from "./pages/AlertsPage";
import "./App.css";

function App() {
  return (
    <div className="app-shell">
      <header className="app-header">
        <Link to="/" className="app-title">
          DetectAI
        </Link>
        <span className="app-subtitle">Evidence-first alert triage</span>
      </header>
      <main className="app-main">
        <Routes>
          <Route path="/" element={<AlertsPage />} />
          <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;
