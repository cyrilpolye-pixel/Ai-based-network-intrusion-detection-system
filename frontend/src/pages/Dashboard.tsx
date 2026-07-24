export default function Dashboard() {
  const stats = [
    {
      title: "Packets Today",
      value: "126,340",
    },
    {
      title: "Threats Detected",
      value: "18",
    },
    {
      title: "Blocked IPs",
      value: "7",
    },
    {
      title: "System Status",
      value: "Protected",
    },
  ];

  return (
    <div>
      <h1
        style={{
          color: "white",
          marginBottom: "25px",
        }}
      >
        Dashboard
      </h1>

      {/* Statistics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4,1fr)",
          gap: "20px",
        }}
      >
        {stats.map((card) => (
          <div
            key={card.title}
            style={{
              background: "#1e293b",
              padding: "20px",
              borderRadius: "10px",
              color: "white",
            }}
          >
            <h3>{card.title}</h3>

            <h1>{card.value}</h1>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "2fr 1fr",
          gap: "20px",
          marginTop: "30px",
        }}
      >
        <div
          style={{
            background: "#1e293b",
            height: "320px",
            borderRadius: "10px",
            padding: "20px",
            color: "white",
          }}
        >
          <h2>Network Traffic</h2>

          <div
            style={{
              height: "230px",
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              color: "#94a3b8",
            }}
          >
            Traffic Chart Placeholder
          </div>
        </div>

        <div
          style={{
            background: "#1e293b",
            height: "320px",
            borderRadius: "10px",
            padding: "20px",
            color: "white",
          }}
        >
          <h2>Threat Distribution</h2>

          <div
            style={{
              height: "230px",
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              color: "#94a3b8",
            }}
          >
            Pie Chart Placeholder
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div
        style={{
          marginTop: "30px",
          background: "#1e293b",
          borderRadius: "10px",
          padding: "20px",
          color: "white",
        }}
      >
        <h2>Recent Intrusion Alerts</h2>

        <table
          style={{
            width: "100%",
            marginTop: "20px",
            borderCollapse: "collapse",
          }}
        >
          <thead>
            <tr>
              <th align="left">Time</th>
              <th align="left">Attack</th>
              <th align="left">Severity</th>
              <th align="left">Status</th>
            </tr>
          </thead>

          <tbody>
            <tr>
              <td>12:01</td>
              <td>DDoS Attack</td>
              <td>Critical</td>
              <td>Blocked</td>
            </tr>

            <tr>
              <td>12:12</td>
              <td>SQL Injection</td>
              <td>High</td>
              <td>Investigating</td>
            </tr>

            <tr>
              <td>12:28</td>
              <td>Port Scan</td>
              <td>Medium</td>
              <td>Detected</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}