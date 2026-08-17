import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import api from "../services/api";
import "./Incident.css";

type Alert = {
  _id: string;
  trafficLogId?: string | { _id?: string };
  attackType: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  status: "Unread" | "Read" | "Resolved";
  time?: string;
  createdAt?: string;
};

type TrafficLog = {
  _id: string;
  timestamp?: string;
  createdAt?: string;
  srcIP?: string;
  dstIP?: string;
  protocol?: string;
  srcPort?: number;
  dstPort?: number;
  duration?: number;
  packets?: number;
  bytes?: number;
  label?: string;
  prediction?: string;
  confidence?: number;
};

export default function Incident() {
  const { alertId } = useParams();
  const navigate = useNavigate();

  const [alert, setAlert] = useState<Alert | null>(null);
  const [traffic, setTraffic] = useState<TrafficLog | null>(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadIncident = async () => {
      if (!alertId) {
        setError("No incident ID was provided.");
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        setError("");

        const [alertsResponse, trafficResponse] =
          await Promise.all([
            api.get("/alerts"),
            api.get("/traffic"),
          ]);

        const alerts: Alert[] =
          alertsResponse.data.alerts || [];

        const trafficLogs: TrafficLog[] =
          trafficResponse.data.traffic || [];

        const selectedAlert = alerts.find(
          (item) => item._id === alertId
        );

        if (!selectedAlert) {
          setError("Incident alert was not found.");
          return;
        }

        setAlert(selectedAlert);

        let trafficId: string | undefined;

        if (typeof selectedAlert.trafficLogId === "string") {
          trafficId = selectedAlert.trafficLogId;
        } else {
          trafficId =
            selectedAlert.trafficLogId?._id;
        }

        if (trafficId) {
          const selectedTraffic = trafficLogs.find(
            (item) => item._id === trafficId
          );

          setTraffic(selectedTraffic || null);
        }
      } catch (err: any) {
        console.error(
          "Failed to load incident details:",
          err
        );

        setError(
          err.response?.data?.message ||
            "Unable to load incident details."
        );
      } finally {
        setLoading(false);
      }
    };

    loadIncident();
  }, [alertId]);

  const formatDate = (value?: string) => {
    if (!value) {
      return "-";
    }

    return new Date(value).toLocaleString();
  };

  const formatBytes = (value?: number) => {
    if (
      value === undefined ||
      value === null ||
      Number.isNaN(value)
    ) {
      return "-";
    }

    if (value === 0) {
      return "0 B";
    }

    const units = ["B", "KB", "MB", "GB"];

    const index = Math.min(
      Math.floor(Math.log(value) / Math.log(1024)),
      units.length - 1
    );

    return `${(
      value / Math.pow(1024, index)
    ).toFixed(2)} ${units[index]}`;
  };

  const formatDuration = (value?: number) => {
    if (
      value === undefined ||
      value === null ||
      Number.isNaN(value)
    ) {
      return "-";
    }

    return value >= 1000
      ? `${(value / 1000).toFixed(2)} s`
      : `${value} ms`;
  };

  const formatConfidence = (value?: number) => {
    if (
      value === undefined ||
      value === null ||
      Number.isNaN(value)
    ) {
      return "-";
    }

    const percentage =
      value <= 1 ? value * 100 : value;

    return `${percentage.toFixed(2)}%`;
  };

  if (loading) {
    return (
      <div className="incident-page">
        <h1 className="incident-title">
          Incident Details
        </h1>

        <div className="incident-card">
          <p className="incident-message">
            Loading incident details...
          </p>
        </div>
      </div>
    );
  }

  if (error || !alert) {
    return (
      <div className="incident-page">
        <h1 className="incident-title">
          Incident Details
        </h1>

        <div className="incident-card">
          <div className="incident-error">
            {error || "Incident not found."}
          </div>

          <button
            className="incident-button incident-button-primary"
            onClick={() => navigate("/alerts")}
          >
            Back to Alerts
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="incident-page">
      <div className="incident-header">
        <div>
          <h1 className="incident-title">
            Incident Details
          </h1>

          <p className="incident-subtitle">
            Details from the selected intrusion alert
            and associated traffic record.
          </p>
        </div>

        <button
          className="incident-button incident-button-primary"
          onClick={() => navigate("/alerts")}
        >
          Back to Alerts
        </button>
      </div>

      <div className="incident-card">
        <table className="incident-table">
          <tbody>
            <TableRow
              label="Attack Type"
              value={alert.attackType}
            />

            <tr>
              <td className="incident-label">
                Severity
              </td>

              <td
                className={`incident-value incident-severity-${alert.severity.toLowerCase()}`}
              >
                {alert.severity}
              </td>
            </tr>

            <tr>
              <td className="incident-label">
                Status
              </td>

              <td
                className={`incident-value incident-status-${alert.status.toLowerCase()}`}
              >
                {alert.status}
              </td>
            </tr>

            <TableRow
              label="Alert Time"
              value={formatDate(
                alert.time || alert.createdAt
              )}
            />

            <TableRow
              label="Source IP"
              value={traffic?.srcIP || "-"}
            />

            <TableRow
              label="Source Port"
              value={traffic?.srcPort ?? "-"}
            />

            <TableRow
              label="Destination IP"
              value={traffic?.dstIP || "-"}
            />

            <TableRow
              label="Destination Port"
              value={traffic?.dstPort ?? "-"}
            />

            <TableRow
              label="Protocol"
              value={traffic?.protocol || "-"}
            />

            <TableRow
              label="Duration"
              value={formatDuration(
                traffic?.duration
              )}
            />

            <TableRow
              label="Packet Count"
              value={
                traffic?.packets !== undefined
                  ? traffic.packets.toLocaleString()
                  : "-"
              }
            />

            <TableRow
              label="Data Transferred"
              value={formatBytes(traffic?.bytes)}
            />

            <TableRow
              label="Traffic Label"
              value={traffic?.label || "-"}
            />

            <TableRow
              label="Prediction"
              value={traffic?.prediction || "-"}
            />

            <TableRow
              label="Prediction Confidence"
              value={formatConfidence(
                traffic?.confidence
              )}
            />
          </tbody>
        </table>
      </div>

      {!traffic && (
        <div className="incident-warning">
          This alert does not have a matching traffic
          record available.
        </div>
      )}
    </div>
  );
}

type RowProps = {
  label: string;
  value: string | number;
};

function TableRow({
  label,
  value,
}: RowProps) {
  return (
    <tr>
      <td className="incident-label">
        {label}
      </td>

      <td className="incident-value">
        {value}
      </td>
    </tr>
  );
}