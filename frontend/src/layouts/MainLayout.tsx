import { useState } from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "../components/Sidebar";
import Topbar from "../components/Topbar";
import "./MainLayout.css";

export default function MainLayout() {
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  const handleToggleSidebar = () => {
    setMobileSidebarOpen((prev) => !prev);
  };

  const handleCloseSidebar = () => {
    setMobileSidebarOpen(false);
  };

  return (
    <div className="main-layout">
      {/* Mobile Backdrop */}
      <div
        className={`sidebar-backdrop ${mobileSidebarOpen ? "active" : ""}`}
        onClick={handleCloseSidebar}
        aria-hidden="true"
      />

      {/* Responsive Sidebar */}
      <Sidebar
        isOpen={mobileSidebarOpen}
        onClose={handleCloseSidebar}
      />

      {/* Main Content Area */}
      <div className="main-content-wrapper">
        <Topbar onToggleSidebar={handleToggleSidebar} />

        <main className="main-content-scroll">
          <Outlet />
        </main>
      </div>
    </div>
  );
}