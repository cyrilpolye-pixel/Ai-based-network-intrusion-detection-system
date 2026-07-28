import { Outlet } from "react-router-dom";
import Sidebar from "../components/Sidebar";
import Topbar from "../components/Topbar";

export default function MainLayout() {
  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        background: "#0f172a",
      }}
    >
      {/* Sidebar */}
      <Sidebar />

      {/* Main Content */}
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
        }}
      >
        <Topbar />

       <div
    style={{
        flex: 1,
        padding: "25px",
        overflowY: "auto",
        overflowX: "hidden",
        background: "#0f172a",
    }}
>
          <Outlet />
        </div>
      </div>
    </div>
  );
}