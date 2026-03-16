import type { ReactNode } from "react";
import Sidebar from "../components/Sidebar";
import Topbar from "../components/Topbar";

interface DashboardLayoutProps {
  children: ReactNode;
}

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  return (
    <div className="grid-bg relative min-h-screen">
      {/* Scan line effect */}
      <div className="scan-line" />

      {/* Sidebar */}
      <Sidebar />

      {/* Main content area */}
      <div className="ml-[72px] flex min-h-screen flex-col">
        {/* Topbar */}
        <Topbar />

        {/* Page content */}
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
