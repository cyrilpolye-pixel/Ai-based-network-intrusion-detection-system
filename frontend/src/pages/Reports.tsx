import * as React from "react";

type Report = {
  id: number;
  name: string;
  date: string;
  status: "Generated" | "Pending" | "Failed";
};

const Reports = () => {
  const reports: Report[] = [
    { id: 1, name: "Daily Traffic Report", date: "2026-07-27", status: "Generated" },
    { id: 2, name: "Intrusion Summary", date: "2026-07-26", status: "Generated" },
    { id: 3, name: "Weekly Analysis", date: "2026-07-25", status: "Pending" },
    { id: 4, name: "System Health Report", date: "2026-07-24", status: "Failed" },
  ];

  return (
    <div style={{ padding: "20px", color: "white" }}>
      <h2>Reports</h2>

      <table width="100%" border={1} cellPadding={10}>
        <thead>
          <tr>
            <th>Report Name</th>
            <th>Date</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>

        <tbody>
          {reports.map((report) => (
            <tr key={report.id}>
              <td>{report.name}</td>
              <td>{report.date}</td>

              <td
                style={{
                  color:
                    report.status === "Generated"
                      ? "lightgreen"
                      : report.status === "Pending"
                      ? "orange"
                      : "red",
                  fontWeight: "bold",
                }}
              >
                {report.status}
              </td>

              <td>
                {report.status === "Generated" ? (
                  <button
                    style={{
                      padding: "5px 10px",
                      background: "#3b82f6",
                      border: "none",
                      color: "white",
                      cursor: "pointer",
                    }}
                  >
                    Download
                  </button>
                ) : (
                  <button
                    style={{
                      padding: "5px 10px",
                      background: "#6b7280",
                      border: "none",
                      color: "white",
                      cursor: "not-allowed",
                    }}
                    disabled
                  >
                    Not Available
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default Reports;