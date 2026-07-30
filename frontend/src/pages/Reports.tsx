type Report = {
  id: number;
  name: string;
  date: string;
  status: "Generated" | "Pending" | "Failed";
  size: string;
};

export default function Reports() {
  const reports: Report[] = [
    {
      id: 1,
      name: "Daily Traffic Report",
      date: "28 Jul 2026",
      status: "Generated",
      size: "2.4 MB",
    },
    {
      id: 2,
      name: "Intrusion Summary",
      date: "27 Jul 2026",
      status: "Generated",
      size: "1.8 MB",
    },
    {
      id: 3,
      name: "Weekly Analysis",
      date: "26 Jul 2026",
      status: "Pending",
      size: "--",
    },
    {
      id: 4,
      name: "System Health Report",
      date: "25 Jul 2026",
      status: "Failed",
      size: "--",
    },
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case "Generated":
        return "#22c55e";
      case "Pending":
        return "#f59e0b";
      default:
        return "#ef4444";
    }
  };

  return (
    <div style={{ color: "white" }}>
      <h1 style={{ marginBottom: "25px" }}>Reports</h1>

      {/* Summary Cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3,1fr)",
          gap: "20px",
          marginBottom: "25px",
        }}
      >
        <Card title="Generated Reports" value="28" />

        <Card title="Pending Reports" value="3" />

        <Card title="Failed Reports" value="1" />
      </div>

      {/* Reports Table */}

      <div
        style={{
          background: "#1e293b",
          border: "1px solid #334155",
          borderRadius: "12px",
          overflow: "hidden",
        }}
      >
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
          }}
        >
          <thead>
            <tr
              style={{
                background: "#111827",
              }}
            >
              <th style={headerStyle}>Report</th>
              <th style={headerStyle}>Date</th>
              <th style={headerStyle}>Size</th>
              <th style={headerStyle}>Status</th>
              <th style={headerStyle}>Action</th>
            </tr>
          </thead>

          <tbody>
            {reports.map((report) => (
              <tr
                key={report.id}
                style={{
                  borderBottom: "1px solid #334155",
                }}
              >
                <td style={cellStyle}>{report.name}</td>

                <td style={cellStyle}>{report.date}</td>

                <td style={cellStyle}>{report.size}</td>

                <td
                  style={{
                    ...cellStyle,
                    color: getStatusColor(report.status),
                    fontWeight: "bold",
                  }}
                >
                  {report.status}
                </td>

                <td style={cellStyle}>
                  {report.status === "Generated" ? (
                    <button style={downloadButton}>
                      Download
                    </button>
                  ) : (
                    <button
                      style={disabledButton}
                      disabled
                    >
                      Unavailable
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Bottom Buttons */}

      <div
        style={{
          display: "flex",
          gap: "20px",
          marginTop: "25px",
        }}
      >
        <button style={primaryButton}>
          Generate New Report
        </button>

        <button style={secondaryButton}>
          Export All
        </button>
      </div>
    </div>
  );
}

type CardProps = {
  title: string;
  value: string;
};

function Card({ title, value }: CardProps) {
  return (
    <div
      style={{
        background: "#1e293b",
        border: "1px solid #334155",
        borderRadius: "12px",
        padding: "20px",
      }}
    >
      <h3
        style={{
          color: "#94a3b8",
          marginBottom: "10px",
        }}
      >
        {title}
      </h3>

      <h1>{value}</h1>
    </div>
  );
}

const headerStyle = {
  padding: "15px",
  textAlign: "left" as const,
  color: "#cbd5e1",
};

const cellStyle = {
  padding: "15px",
};

const primaryButton = {
  background: "#3b82f6",
  color: "white",
  border: "none",
  padding: "10px 18px",
  borderRadius: "8px",
  cursor: "pointer",
};

const secondaryButton = {
  background: "#334155",
  color: "white",
  border: "none",
  padding: "10px 18px",
  borderRadius: "8px",
  cursor: "pointer",
};

const downloadButton = {
  background: "#22c55e",
  color: "white",
  border: "none",
  padding: "8px 14px",
  borderRadius: "6px",
  cursor: "pointer",
};

const disabledButton = {
  background: "#475569",
  color: "#cbd5e1",
  border: "none",
  padding: "8px 14px",
  borderRadius: "6px",
  cursor: "not-allowed",
};