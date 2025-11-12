import React, {
  useState,
  useEffect,
  createContext,
  useContext,
  useRef,
} from "react";
import ReactDOM from "react-dom/client";
import { HashRouter, Routes, Route, Link, useLocation } from "react-router-dom";
// FIX: Import CryptoJS to resolve reference errors in the Backup component.
import CryptoJS from "crypto-js";

const API_BASE_URL = "http://localhost:3001/api";

const UserContext = createContext(null);
const ToastContext = createContext(null);

const securityQuestions = [
  "What was the name of your first pet?",
  "What is your mother's maiden name?",
  "What was the name of your elementary school?",
  "In what city were you born?",
  "What is the name of your favorite childhood friend?",
  "What was the first company you worked for?",
  "What is your favorite movie?",
  "What is the make of your first car?",
];

// --- Toast Notification System ---
const useToast = () => useContext(ToastContext);

const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([]);
  let toastCount = 0;

  const addToast = (message, type = "info") => {
    const id = toastCount++;
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => removeToast(id), 5000);
  };

  const removeToast = (id) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  };

  return (
    <ToastContext.Provider value={{ addToast }}>
      {children}
      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </ToastContext.Provider>
  );
};

const ToastContainer = ({ toasts, removeToast }) => (
  <div className="toast-container">
    {toasts.map((toast) => (
      <Toast
        key={toast.id}
        {...toast}
        onDismiss={() => removeToast(toast.id)}
      />
    ))}
  </div>
);

const Toast = ({ message, type, onDismiss }) => {
  const [isExiting, setIsExiting] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsExiting(true);
      setTimeout(onDismiss, 300);
    }, 4700);
    return () => clearTimeout(timer);
  }, [onDismiss]);

  const icons = {
    success: (
      <svg
        className="toast-icon"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M22 11.08V12a10 10 0 1 1-5.93-9.14"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M22 4L12 14.01l-3-3"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    ),
    error: (
      <svg
        className="toast-icon"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <circle
          cx="12"
          cy="12"
          r="10"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M12 8v4"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M12 16h.01"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    ),
    info: (
      <svg
        className="toast-icon"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <circle
          cx="12"
          cy="12"
          r="10"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M12 16v-4"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M12 8h.01"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    ),
  };

  return (
    <div className={`toast ${type} ${isExiting ? "exiting" : ""}`}>
      {icons[type]}
      <span>{message}</span>
    </div>
  );
};

// --- Confirmation Modal ---
const ConfirmationModal = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  children,
}: React.PropsWithChildren<{
  isOpen: any;
  onClose: any;
  onConfirm: any;
  title: any;
}>) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay visible">
      <div className="modal-content">
        <h2>{title}</h2>
        <p>{children}</p>
        <div className="modal-actions">
          <button className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-danger" onClick={onConfirm}>
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
};

const checkPasswordStrength = (
  password: string
): { score: number; feedback: string } => {
  let score = 0;
  let feedback = "Very Weak";

  if (!password || password.length === 0) return { score: 0, feedback: "" };

  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  switch (score) {
    case 0:
      feedback = "Very Weak";
      break;
    case 1:
      feedback = "Weak";
      break;
    case 2:
      feedback = "Moderate";
      break;
    case 3:
      feedback = "Good";
      break;
    case 4:
      feedback = "Strong";
      break;
    case 5:
      feedback = "Very Strong";
      break;
  }
  return { score, feedback };
};

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalPasswords: 0,
    weakPasswords: 0,
    securityScore: 0,
    strongest: "N/A",
    weakest: "N/A",
  });
  const [isLoading, setIsLoading] = useState(true);
  const loggedInUser = useContext(UserContext);
  const toast = useToast();

  const calculateDashboardMetrics = (vaultData) => {
    if (!vaultData || vaultData.length === 0) {
      setIsLoading(false);
      return;
    }

    const totalPasswords = vaultData.length;
    let weakPasswords = 0;
    let totalScore = 0;
    let strongest = { service: "N/A", score: -1 };
    let weakest = { service: "N/A", score: 6 };

    vaultData.forEach((item) => {
      if (item.password && item.password.length > 0) {
        const strength = checkPasswordStrength(item.password);
        totalScore += strength.score;

        if (strength.score <= 2) {
          // Weak or Moderate
          weakPasswords++;
        }

        if (strength.score > strongest.score) {
          strongest = { service: item.service, score: strength.score };
        }

        if (strength.score < weakest.score) {
          weakest = { service: item.service, score: strength.score };
        }
      } else {
        // Empty passwords are the weakest
        weakPasswords++;
        if (0 < weakest.score) {
          weakest = { service: item.service, score: 0 };
        }
      }
    });

    const averageScore = totalPasswords > 0 ? totalScore / totalPasswords : 0;
    const securityScore = Math.round((averageScore / 5) * 100);

    setStats({
      totalPasswords,
      weakPasswords,
      securityScore,
      strongest: strongest.service,
      weakest: weakest.service,
    });
    setIsLoading(false);
  };

  useEffect(() => {
    const fetchVaultDataForDashboard = async () => {
      if (!loggedInUser) return;
      try {
        setIsLoading(true);
        const response = await fetch(`${API_BASE_URL}/vault`, {
          headers: { "X-User-ID": loggedInUser.id },
        });
        const data = await response.json();
        calculateDashboardMetrics(data);
      } catch (error) {
        console.error("Failed to fetch vault data for dashboard:", error);
        toast.addToast("Failed to load dashboard data.", "error");
        setIsLoading(false);
      }
    };
    fetchVaultDataForDashboard();
  }, [loggedInUser]);

  if (isLoading) {
    return (
      <div className="page-content">
        <div className="dashboard-grid">
          <div
            className="card"
            style={{ gridColumn: "1 / -1", textAlign: "center" }}
          >
            Loading Dashboard...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="page-content">
      <div className="dashboard-grid">
        {/* Security Score */}
        <div className="card">
          <div className="card-header">
            <svg
              className="icon"
              style={{ color: "var(--text-primary-color)" }}
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M12 22S19 18 19 12V5L12 2L5 5V12C5 18 12 22 12 22Z"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M9 12L11 14L15 10"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <span>Security Score</span>
          </div>
          <p className="card-subtitle">An overview of your security health.</p>
          <div className="progress-bar">
            <div
              className="progress"
              style={{ width: `${stats.securityScore}%` }}
            ></div>
          </div>
          <div className="progress-label">{stats.securityScore}%</div>
        </div>
        {/* Vault Statistics */}
        <div className="card">
          <div className="card-header">
            <svg
              className="icon"
              style={{ color: "var(--accent-color-blue)" }}
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M7 11V7C7 5.67392 7.52678 4.40215 8.46447 3.46447C9.40215 2.52678 10.6739 2 12 2C13.3261 2 14.5979 2.52678 15.5355 3.46447C16.4732 4.40215 17 5.67392 17 7V11"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M4 22H20V11H4V22Z"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <span>Vault Statistics</span>
          </div>
          <p className="card-subtitle">Total entries and weak passwords.</p>
          <div style={{ marginTop: "auto" }}>
            <div className="vault-stats">
              <span>Total Passwords:</span> <span>{stats.totalPasswords}</span>
            </div>
            <div className="vault-stats">
              <span>Weak Passwords:</span>{" "}
              <span style={{ color: "var(--accent-color-red)" }}>
                {stats.weakPasswords}
              </span>
            </div>
          </div>
        </div>
        {/* Quick Actions */}
        <div className="card">
          <div className="card-header">
            <svg
              className="icon"
              style={{ color: "var(--accent-color-green)" }}
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M12 5V19"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M5 12H19"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <span>Quick Actions</span>
          </div>
          <p className="card-subtitle">Access key features instantly.</p>
          <button
            className="btn btn-primary"
            onClick={() =>
              toast.addToast(
                "Password Generator is in the Tools section!",
                "info"
              )
            }
          >
            Generate a Strong Password
          </button>
        </div>
        {/* Breach Monitoring */}
        <div className="card">
          <div className="card-header">
            <svg
              className="icon"
              style={{ color: "var(--accent-color-red)" }}
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M13 2L3 14H12L11 22L21 10H12L13 2Z"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <span>Breach Monitoring</span>
          </div>
          <p className="card-subtitle">
            Check your passwords against known data breaches.
          </p>
          <p style={{ margin: "auto 0" }}>No scan has been run.</p>
          <button
            className="btn btn-danger"
            onClick={() =>
              toast.addToast("Breach monitoring coming soon!", "info")
            }
          >
            Scan for Breaches
          </button>
        </div>
        {/* Password Highlights */}
        <div className="card">
          <div className="card-header">
            <svg
              className="icon"
              style={{ color: "var(--accent-color-yellow)" }}
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M12 2L15.09 8.26L22 9.27L17 14.14L18.18 21.02L12 17.77L5.82 21.02L7 14.14L2 9.27L8.91 8.26L12 2Z"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <span>Password Highlights</span>
          </div>
          <p className="card-subtitle">Your strongest and weakest passwords.</p>
          <div className="password-highlights" style={{ marginTop: "auto" }}>
            <div className="strong" style={{ marginBottom: "0.5rem" }}>
              Strongest: <a href="#">{stats.strongest}</a>
            </div>
            <div className="weak">
              Weakest: <a href="#">{stats.weakest}</a>
            </div>
          </div>
        </div>
        {/* Recent Activity */}
        <div className="card">
          <div className="card-header">
            <svg
              className="icon"
              style={{ color: "var(--text-secondary-color)" }}
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M12 6V12L16 14"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <span>Recent Activity</span>
          </div>
          <p className="card-subtitle">Last few actions taken.</p>
          <div className="recent-activity">
            <ul>
              <li>• Vault unlocked.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

const VaultCarousel = () => {
  const [vaultData, setVaultData] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeIndex, setActiveIndex] = useState(0);
  const [passwordsVisible, setPasswordsVisible] = useState<{
    [key: number]: boolean;
  }>({});
  const [searchQuery, setSearchQuery] = useState("");
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingEntry, setEditingEntry] = useState(null);
  const [newEntry, setNewEntry] = useState({
    service: "",
    username: "",
    password: "",
  });
  const loggedInUser = useContext(UserContext);
  const toast = useToast();
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [itemToDelete, setItemToDelete] = useState(null);

  const fetchVaultData = async () => {
    if (!loggedInUser) return;
    try {
      setIsLoading(true);
      const response = await fetch(`${API_BASE_URL}/vault`, {
        headers: { "X-User-ID": loggedInUser.id },
      });
      const data = await response.json();
      setVaultData(data);
    } catch (error) {
      console.error("Failed to fetch vault data:", error);
      toast.addToast("Failed to fetch vault data.", "error");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchVaultData();
  }, [loggedInUser]);

  useEffect(() => {
    if (isModalOpen) {
      if (editingEntry) {
        setNewEntry(editingEntry);
      } else {
        setNewEntry({ service: "", username: "", password: "" });
      }
    } else {
      setEditingEntry(null);
    }
  }, [isModalOpen, editingEntry]);

  const handleCopy = (text: string, type: "Username" | "Password") => {
    if (text === null || typeof text === "undefined") {
      console.warn("Attempted to copy null or undefined text.");
      return;
    }
    navigator.clipboard.writeText(text).then(() => {
      toast.addToast(`${type} copied to clipboard!`, "success");
    });
  };

  const togglePasswordVisibility = (id: number) => {
    setPasswordsVisible((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleNext = () => {
    if (vaultData.length === 0) return;
    setActiveIndex((prevIndex) => (prevIndex + 1) % vaultData.length);
  };

  const handlePrev = () => {
    if (vaultData.length === 0) return;
    setActiveIndex(
      (prevIndex) => (prevIndex - 1 + vaultData.length) % vaultData.length
    );
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const query = e.target.value;
    setSearchQuery(query);

    if (query) {
      const foundIndex = vaultData.findIndex((item) =>
        item.service.toLowerCase().startsWith(query.toLowerCase())
      );
      if (foundIndex !== -1) {
        setActiveIndex(foundIndex);
      }
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setNewEntry((prev) => ({ ...prev, [name]: value }));
  };

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!newEntry.service || !newEntry.username) {
      toast.addToast("Please fill Site Name and Username fields.", "error");
      return;
    }

    const method = editingEntry ? "PUT" : "POST";
    const url = editingEntry
      ? `${API_BASE_URL}/vault/${editingEntry.id}`
      : `${API_BASE_URL}/vault`;

    try {
      const response = await fetch(url, {
        method,
        headers: {
          "Content-Type": "application/json",
          "X-User-ID": loggedInUser.id,
        },
        body: JSON.stringify(newEntry),
      });
      if (response.ok) {
        fetchVaultData();
        setIsModalOpen(false);
        toast.addToast(
          `Vault entry ${editingEntry ? "updated" : "saved"} successfully!`,
          "success"
        );
      } else {
        throw new Error("Server responded with an error.");
      }
    } catch (error) {
      console.error(
        `Error ${editingEntry ? "updating" : "saving"} entry:`,
        error
      );
      toast.addToast(
        `Failed to ${editingEntry ? "update" : "save"} entry.`,
        "error"
      );
    }
  };

  const confirmDelete = (id: number) => {
    setItemToDelete(id);
    setIsConfirmOpen(true);
  };

  const handleDelete = async () => {
    if (itemToDelete === null) return;
    try {
      const response = await fetch(`${API_BASE_URL}/vault/${itemToDelete}`, {
        method: "DELETE",
        headers: { "X-User-ID": loggedInUser.id },
      });
      if (response.ok) {
        setActiveIndex(0);
        fetchVaultData();
        toast.addToast("Vault entry deleted.", "success");
      } else {
        throw new Error("Server responded with an error.");
      }
    } catch (error) {
      console.error("Error deleting entry:", error);
      toast.addToast("Failed to delete entry.", "error");
    } finally {
      setIsConfirmOpen(false);
      setItemToDelete(null);
    }
  };

  const handleEdit = (item: any) => {
    setEditingEntry(item);
    setIsModalOpen(true);
  };

  const getCardStyle = (index: number) => {
    const offset = index - activeIndex;
    const total = vaultData.length;

    let normalizedOffset = offset;
    if (offset > total / 2) {
      normalizedOffset -= total;
    } else if (offset < -total / 2) {
      normalizedOffset += total;
    }

    const zIndex = total - Math.abs(normalizedOffset);
    const scale = 1 - Math.abs(normalizedOffset) * 0.05;
    const opacity =
      Math.abs(normalizedOffset) > 2 ? 0 : 1 - Math.abs(normalizedOffset) * 0.3;
    const transform = `translateX(${normalizedOffset * 50}px) translateZ(${
      -Math.abs(normalizedOffset) * 50
    }px) scale(${scale})`;

    return {
      transform,
      opacity,
      zIndex,
    };
  };

  return (
    <div className="page-content">
      <div className="vault-container">
        <ConfirmationModal
          isOpen={isConfirmOpen}
          onClose={() => setIsConfirmOpen(false)}
          onConfirm={handleDelete}
          title="Delete Vault Entry?"
        >
          Are you sure you want to permanently delete this entry? This action
          cannot be undone.
        </ConfirmationModal>

        {isModalOpen && (
          <div className="modal-overlay visible">
            <div className="modal-content">
              <button
                className="modal-close-btn"
                onClick={() => setIsModalOpen(false)}
              >
                &times;
              </button>
              <h2>{editingEntry ? "Edit" : "Add New"} Vault Entry</h2>
              <form onSubmit={handleFormSubmit} className="modal-form">
                <div className="modal-form-group">
                  <label htmlFor="service">Site Name</label>
                  <input
                    type="text"
                    id="service"
                    name="service"
                    value={newEntry.service}
                    onChange={handleInputChange}
                    required
                  />
                </div>
                <div className="modal-form-group">
                  <label htmlFor="username">Username</label>
                  <input
                    type="text"
                    id="username"
                    name="username"
                    value={newEntry.username}
                    onChange={handleInputChange}
                    required
                  />
                </div>
                <div className="modal-form-group">
                  <label htmlFor="password">Password</label>
                  <input
                    type="text"
                    id="password"
                    name="password"
                    value={newEntry.password}
                    onChange={handleInputChange}
                  />
                </div>
                <div className="modal-actions">
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => setIsModalOpen(false)}
                  >
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary">
                    {editingEntry ? "Update" : "Save"} Entry
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        <div className="carousel-container">
          <div
            className="carousel-nav prev"
            onClick={handlePrev}
            role="button"
            aria-label="Previous"
          >
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M15 18L9 12L15 6"
                stroke="white"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <div className="carousel-content-wrapper">
            <div className="vault-controls">
              <div className="search-bar-container">
                <svg
                  className="search-icon"
                  width="20"
                  height="20"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M11 19C15.4183 19 19 15.4183 19 11C19 6.58172 15.4183 3 11 3C6.58172 3 3 6.58172 3 11C3 15.4183 6.58172 19 11 19Z"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M21 21L16.65 16.65"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
                <input
                  type="text"
                  className="search-input"
                  placeholder="Search by site name..."
                  value={searchQuery}
                  onChange={handleSearchChange}
                />
              </div>
              <button
                className="btn btn-primary add-btn"
                onClick={() => setIsModalOpen(true)}
              >
                Add New Entry
              </button>
            </div>
            <div className="carousel-stack">
              {isLoading ? (
                <div className="loading-state">Loading Vault...</div>
              ) : vaultData.length === 0 ? (
                <div className="empty-state">
                  Your vault is empty. Add an entry to get started!
                </div>
              ) : (
                vaultData.map((item, index) => (
                  <div
                    className="carousel-card"
                    key={item.id}
                    style={getCardStyle(index)}
                  >
                    <div className="card-login-theme">
                      <h3 className="service-name">{item.service}</h3>
                      <hr className="separator" />

                      <div className="field-group">
                        <label>Username</label>
                        <div className="field-value-box">
                          <span className="field-text">{item.username}</span>
                          <button
                            className="copy-btn"
                            onClick={() =>
                              handleCopy(item.username, "Username")
                            }
                            aria-label="Copy Username"
                          >
                            COPY
                          </button>
                        </div>
                      </div>

                      <div className="field-group">
                        <label>Password</label>
                        <div className="field-value-box">
                          <span className="field-text">
                            {passwordsVisible[item.id]
                              ? item.password
                              : "••••••••••••••••"}
                          </span>
                          <div className="password-actions">
                            <button
                              className="copy-btn"
                              onClick={() =>
                                handleCopy(item.password, "Password")
                              }
                              aria-label="Copy Password"
                            >
                              COPY
                            </button>
                            <button
                              className="icon-btn"
                              onClick={() => togglePasswordVisibility(item.id)}
                              aria-label="Toggle password visibility"
                            >
                              {passwordsVisible[item.id] ? (
                                <svg
                                  width="20"
                                  height="20"
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  xmlns="http://www.w3.org/2000/svg"
                                  stroke="currentColor"
                                  strokeWidth="2"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                >
                                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                                  <line x1="1" y1="1" x2="23" y2="23" />
                                </svg>
                              ) : (
                                <svg
                                  width="20"
                                  height="20"
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  xmlns="http://www.w3.org/2000/svg"
                                  stroke="currentColor"
                                  strokeWidth="2"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                >
                                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                                  <circle cx="12" cy="12" r="3" />
                                </svg>
                              )}
                            </button>
                          </div>
                        </div>
                      </div>

                      <div className="card-actions">
                        <button
                          className="action-btn edit"
                          onClick={() => handleEdit(item)}
                        >
                          EDIT
                        </button>
                        <button
                          className="action-btn delete"
                          onClick={() => confirmDelete(item.id)}
                        >
                          DELETE
                        </button>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
          <div
            className="carousel-nav next"
            onClick={handleNext}
            role="button"
            aria-label="Next"
          >
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M9 18L15 12L9 6"
                stroke="white"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
};

const SecureNotes = () => {
  const [notes, setNotes] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedNote, setSelectedNote] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [isEditing, setIsEditing] = useState(false);
  const [currentNote, setCurrentNote] = useState({ title: "", content: "" });
  const loggedInUser = useContext(UserContext);
  const toast = useToast();
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [itemToDelete, setItemToDelete] = useState(null);
  const [isSwitchingNoteConfirm, setIsSwitchingNoteConfirm] = useState(false);
  const [nextNoteAction, setNextNoteAction] = useState(null);

  const fetchNotes = async () => {
    if (!loggedInUser) return;
    try {
      setIsLoading(true);
      const response = await fetch(`${API_BASE_URL}/notes`, {
        headers: { "X-User-ID": loggedInUser.id },
      });
      const data = await response.json();
      setNotes(data);
      if (data.length === 0) {
        setSelectedNote(null);
      }
    } catch (error) {
      console.error("Failed to fetch notes:", error);
      toast.addToast("Failed to fetch notes.", "error");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchNotes();
  }, [loggedInUser]);

  useEffect(() => {
    if (selectedNote) {
      setCurrentNote({
        title: selectedNote.title,
        content: selectedNote.content,
      });
      setIsEditing(false);
    } else {
      setCurrentNote({ title: "", content: "" });
    }
  }, [selectedNote]);

  const handleUnsavedChanges = (action) => {
    if (isEditing) {
      setNextNoteAction(() => action);
      setIsSwitchingNoteConfirm(true);
    } else {
      action();
    }
  };

  const confirmSwitchNote = () => {
    if (nextNoteAction) {
      nextNoteAction();
    }
    setIsSwitchingNoteConfirm(false);
    setNextNoteAction(null);
  };

  const handleSelectNote = (note) => {
    handleUnsavedChanges(() => setSelectedNote(note));
  };

  const handleNewNote = () => {
    handleUnsavedChanges(() => {
      setSelectedNote(null);
      setCurrentNote({ title: "", content: "" });
      setIsEditing(true);
    });
  };

  const confirmDelete = (id: number) => {
    setItemToDelete(id);
    setIsConfirmOpen(true);
  };

  const handleDelete = async () => {
    if (itemToDelete === null) return;
    try {
      await fetch(`${API_BASE_URL}/notes/${itemToDelete}`, {
        method: "DELETE",
        headers: { "X-User-ID": loggedInUser.id },
      });
      if (selectedNote?.id === itemToDelete) {
        setSelectedNote(null);
      }
      fetchNotes();
      toast.addToast("Note deleted successfully.", "success");
    } catch (error) {
      console.error("Failed to delete note:", error);
      toast.addToast("Failed to delete note.", "error");
    } finally {
      setIsConfirmOpen(false);
      setItemToDelete(null);
    }
  };

  const handleSave = async () => {
    if (!currentNote.title) {
      toast.addToast("Title is required.", "error");
      return;
    }
    const method = selectedNote ? "PUT" : "POST";
    const url = selectedNote
      ? `${API_BASE_URL}/notes/${selectedNote.id}`
      : `${API_BASE_URL}/notes`;

    try {
      const response = await fetch(url, {
        method,
        headers: {
          "Content-Type": "application/json",
          "X-User-ID": loggedInUser.id,
        },
        body: JSON.stringify(currentNote),
      });
      if (response.ok) {
        const savedNote = await response.json();
        await fetchNotes();
        const res = await fetch(`${API_BASE_URL}/notes`, {
          headers: { "X-User-ID": loggedInUser.id },
        });
        const allNotes = await res.json();
        const newSelectedNote = allNotes.find(
          (n) => n.id === (selectedNote?.id || savedNote.id)
        );
        setSelectedNote(newSelectedNote);
        setIsEditing(false);
        toast.addToast("Note saved successfully!", "success");
      } else {
        throw new Error("Failed to save note.");
      }
    } catch (error) {
      console.error("Error saving note:", error);
      toast.addToast("Error saving note.", "error");
    }
  };

  const filteredNotes = notes.filter((note) =>
    note.title.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const renderContent = () => {
    if (isEditing) {
      return (
        <div className="note-editor-view">
          <div className="note-view-header">
            <input
              type="text"
              className="modal-form-group"
              style={{
                width: "100%",
                fontSize: "1.75rem",
                fontWeight: "bold",
                border: "none",
                background: "transparent",
                color: "var(--text-primary-color)",
              }}
              value={currentNote.title}
              onChange={(e) =>
                setCurrentNote({ ...currentNote, title: e.target.value })
              }
              placeholder="Note Title"
            />
            <div className="note-view-actions">
              <button
                className="action-btn"
                onClick={() => {
                  setIsEditing(false);
                  if (selectedNote) setCurrentNote(selectedNote);
                }}
              >
                CANCEL
              </button>
              <button className="action-btn edit" onClick={handleSave}>
                SAVE
              </button>
            </div>
          </div>
          <textarea
            className="modal-form-group"
            style={{ fontFamily: "monospace, sans-serif" }}
            value={currentNote.content}
            onChange={(e) =>
              setCurrentNote({ ...currentNote, content: e.target.value })
            }
            placeholder="Start writing your note..."
          />
        </div>
      );
    }

    if (selectedNote) {
      return (
        <>
          <div className="note-view-header">
            <button
              className="action-btn note-back-btn"
              style={{ display: "none" }}
              onClick={() => setSelectedNote(null)}
            >
              Back
            </button>
            <h2>{selectedNote.title}</h2>
            <div className="note-view-actions">
              <button
                className="action-btn edit"
                onClick={() => setIsEditing(true)}
              >
                EDIT
              </button>
              <button
                className="action-btn delete"
                onClick={() => confirmDelete(selectedNote.id)}
              >
                DELETE
              </button>
            </div>
          </div>
          <div className="note-view-content-wrapper card">
            <pre className="note-view-content">{selectedNote.content}</pre>
          </div>
        </>
      );
    }

    return (
      <div className="note-view-placeholder">
        <svg
          className="icon"
          style={{
            width: "60px",
            height: "60px",
            color: "var(--text-secondary-color)",
          }}
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M14 2V8H20"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M16 13H8"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M16 17H8"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M10 9H8"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
        <h3>Select a note to view</h3>
        <p>Or create a new note to get started.</p>
      </div>
    );
  };

  return (
    <div className="page-content">
      <div
        className={`secure-notes-container ${
          selectedNote || isEditing ? "viewing-note" : ""
        }`}
      >
        <ConfirmationModal
          isOpen={isConfirmOpen}
          onClose={() => setIsConfirmOpen(false)}
          onConfirm={handleDelete}
          title="Delete Note?"
        >
          Are you sure you want to permanently delete this note? This action
          cannot be undone.
        </ConfirmationModal>
        <ConfirmationModal
          isOpen={isSwitchingNoteConfirm}
          onClose={() => setIsSwitchingNoteConfirm(false)}
          onConfirm={confirmSwitchNote}
          title="Unsaved Changes"
        >
          You have unsaved changes. Are you sure you want to discard them?
        </ConfirmationModal>

        <aside className="notes-list-sidebar">
          <div className="notes-list-header">
            <div className="search-bar-container">
              <svg
                className="search-icon"
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M11 19C15.4183 19 19 15.4183 19 11C19 6.58172 15.4183 3 11 3C6.58172 3 3 6.58172 3 11C3 15.4183 6.58172 19 11 19Z"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M21 21L16.65 16.65"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              <input
                type="text"
                className="search-input"
                placeholder="Search notes..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <button
              className="btn btn-primary add-note-btn"
              onClick={handleNewNote}
            >
              <svg
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
                style={{ color: "white", marginRight: "0.5rem" }}
              >
                <path
                  d="M12 5V19"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M5 12H19"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              New Note
            </button>
          </div>
          <div className="notes-list">
            {isLoading ? (
              <div>Loading...</div>
            ) : filteredNotes.length > 0 ? (
              filteredNotes.map((note) => (
                <div
                  key={note.id}
                  className={`note-item ${
                    selectedNote?.id === note.id && !isEditing ? "active" : ""
                  }`}
                  onClick={() => handleSelectNote(note)}
                >
                  <div className="note-item-title">{note.title}</div>
                  <div className="note-item-preview">
                    {note.content.substring(0, 40)}...
                  </div>
                </div>
              ))
            ) : (
              <div className="no-notes-found">No notes found.</div>
            )}
          </div>
        </aside>
        <main className="note-content-view">{renderContent()}</main>
      </div>
    </div>
  );
};

const cardGradients = [
  "linear-gradient(135deg, #6a11cb 0%, #2575fc 100%)",
  "linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%)",
  "linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)",
  "linear-gradient(135deg, #f6d365 0%, #fda085 100%)",
  "linear-gradient(135deg, #00c6ff 0%, #0072ff 100%)",
  "linear-gradient(135deg, #d4fc79 0%, #96e6a1 100%)",
  "linear-gradient(135deg, #fa709a 0%, #fee140 100%)",
];

const CreditCards = () => {
  const [cards, setCards] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingCard, setEditingCard] = useState(null);
  const [newCard, setNewCard] = useState({
    cardholderName: "",
    cardNumber: "",
    expiryMonth: "",
    expiryYear: "",
    cvv: "",
  });
  const [isFlipped, setIsFlipped] = useState<{ [key: number]: boolean }>({});
  const [cvvVisible, setCvvVisible] = useState<{ [key: number]: boolean }>({});
  const loggedInUser = useContext(UserContext);
  const toast = useToast();
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [itemToDelete, setItemToDelete] = useState(null);

  const fetchCards = async () => {
    if (!loggedInUser) return;
    try {
      setIsLoading(true);
      const response = await fetch(`${API_BASE_URL}/cards`, {
        headers: { "X-User-ID": loggedInUser.id },
      });
      const data = await response.json();
      setCards(data);
    } catch (error) {
      console.error("Failed to fetch cards:", error);
      toast.addToast("Failed to fetch cards.", "error");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchCards();
  }, [loggedInUser]);

  useEffect(() => {
    if (isModalOpen) {
      if (editingCard) {
        setNewCard(editingCard);
      } else {
        setNewCard({
          cardholderName: "",
          cardNumber: "",
          expiryMonth: "",
          expiryYear: "",
          cvv: "",
        });
      }
    } else {
      setEditingCard(null);
    }
  }, [isModalOpen, editingCard]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    let formattedValue = value;
    if (name === "cardNumber") {
      formattedValue = value.replace(/\D/g, "").substring(0, 16);
    } else if (name === "expiryMonth") {
      formattedValue = value.replace(/\D/g, "").substring(0, 2);
    } else if (name === "expiryYear") {
      formattedValue = value.replace(/\D/g, "").substring(0, 2);
    } else if (name === "cvv") {
      formattedValue = value.replace(/\D/g, "").substring(0, 4);
    }
    setNewCard((prev) => ({ ...prev, [name]: formattedValue }));
  };

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    // Basic validation
    if (
      !newCard.cardholderName ||
      newCard.cardNumber.length !== 16 ||
      !newCard.expiryMonth ||
      !newCard.expiryYear ||
      !newCard.cvv
    ) {
      toast.addToast("Please fill all fields correctly.", "error");
      return;
    }

    const method = editingCard ? "PUT" : "POST";
    const url = editingCard
      ? `${API_BASE_URL}/cards/${editingCard.id}`
      : `${API_BASE_URL}/cards`;

    const cardPayload = editingCard
      ? { ...newCard }
      : {
          ...newCard,
          gradient: cardGradients[cards.length % cardGradients.length],
        };

    try {
      const response = await fetch(url, {
        method: method,
        headers: {
          "Content-Type": "application/json",
          "X-User-ID": loggedInUser.id,
        },
        body: JSON.stringify(cardPayload),
      });
      if (response.ok) {
        fetchCards();
        setIsModalOpen(false);
        toast.addToast(
          `Card ${editingCard ? "updated" : "saved"} successfully!`,
          "success"
        );
      } else {
        throw new Error("Server returned an error.");
      }
    } catch (error) {
      console.error(
        `Error ${editingCard ? "updating" : "saving"} new card:`,
        error
      );
      toast.addToast(
        `An error occurred while ${editingCard ? "updating" : "saving"}.`,
        "error"
      );
    }
  };

  const confirmDeleteCard = (id: number) => {
    setItemToDelete(id);
    setIsConfirmOpen(true);
  };

  const handleDeleteCard = async () => {
    if (itemToDelete === null) return;
    try {
      await fetch(`${API_BASE_URL}/cards/${itemToDelete}`, {
        method: "DELETE",
        headers: { "X-User-ID": loggedInUser.id },
      });
      fetchCards();
      toast.addToast("Card deleted.", "success");
    } catch (error) {
      console.error("Failed to delete card:", error);
      toast.addToast("Failed to delete card.", "error");
    } finally {
      setIsConfirmOpen(false);
      setItemToDelete(null);
    }
  };

  const handleEditCard = (card: any) => {
    setEditingCard(card);
    setIsModalOpen(true);
  };

  const getCardType = (cardNumber: string) => {
    if (cardNumber.startsWith("4")) return "visa";
    if (cardNumber.startsWith("5")) return "mastercard";
    return "default";
  };

  const formatCardNumber = (cardNumber: string) => {
    return cardNumber.replace(/(\d{4})/g, "$1 ").trim();
  };

  const toggleFlip = (id: number) => {
    setIsFlipped((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleCvvVisibility = (e: React.MouseEvent, id: number) => {
    e.stopPropagation();
    setCvvVisible((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div className="page-content">
      <div className="credit-cards-container">
        <ConfirmationModal
          isOpen={isConfirmOpen}
          onClose={() => setIsConfirmOpen(false)}
          onConfirm={handleDeleteCard}
          title="Delete Credit Card?"
        >
          Are you sure you want to permanently delete this card? This action
          cannot be undone.
        </ConfirmationModal>

        {isModalOpen && (
          <div className="modal-overlay visible">
            <div className="modal-content">
              <button
                className="modal-close-btn"
                onClick={() => setIsModalOpen(false)}
              >
                &times;
              </button>
              <h2>{editingCard ? "Edit" : "Add New"} Credit Card</h2>
              <form onSubmit={handleFormSubmit} className="modal-form">
                <div className="modal-form-group">
                  <label htmlFor="cardholderName">Cardholder Name</label>
                  <input
                    type="text"
                    id="cardholderName"
                    name="cardholderName"
                    value={newCard.cardholderName}
                    onChange={handleInputChange}
                    required
                  />
                </div>
                <div className="modal-form-group">
                  <label htmlFor="cardNumber">Card Number</label>
                  <input
                    type="text"
                    id="cardNumber"
                    name="cardNumber"
                    value={formatCardNumber(newCard.cardNumber)}
                    onChange={handleInputChange}
                    required
                    maxLength={19}
                    placeholder="XXXX XXXX XXXX XXXX"
                  />
                </div>
                <div className="card-input-group">
                  <div className="modal-form-group">
                    <label htmlFor="expiryMonth">Expiry Month</label>
                    <input
                      type="text"
                      id="expiryMonth"
                      name="expiryMonth"
                      value={newCard.expiryMonth}
                      onChange={handleInputChange}
                      required
                      maxLength={2}
                      placeholder="MM"
                    />
                  </div>
                  <div className="modal-form-group">
                    <label htmlFor="expiryYear">Expiry Year</label>
                    <input
                      type="text"
                      id="expiryYear"
                      name="expiryYear"
                      value={newCard.expiryYear}
                      onChange={handleInputChange}
                      required
                      maxLength={2}
                      placeholder="YY"
                    />
                  </div>
                  <div className="modal-form-group">
                    <label htmlFor="cvv">CVV</label>
                    <input
                      type="text"
                      id="cvv"
                      name="cvv"
                      value={newCard.cvv}
                      onChange={handleInputChange}
                      required
                      maxLength={4}
                    />
                  </div>
                </div>
                <div className="modal-actions">
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => setIsModalOpen(false)}
                  >
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary">
                    {editingCard ? "Update" : "Save"} Card
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        <div className="credit-cards-header">
          <h2>Credit Cards</h2>
          <button
            className="btn btn-primary"
            onClick={() => setIsModalOpen(true)}
          >
            Add New Card
          </button>
        </div>
        {isLoading ? (
          <div>Loading cards...</div>
        ) : (
          <div className="cards-grid">
            {cards.map((card) => {
              const cardType = getCardType(card.cardNumber);
              return (
                <div key={card.id} className="credit-card-wrapper">
                  <div
                    className={`credit-card-item ${
                      isFlipped[card.id] ? "flipped" : ""
                    }`}
                    onClick={() => toggleFlip(card.id)}
                  >
                    <div className="credit-card-inner">
                      <div
                        className="credit-card-front"
                        style={{ background: card.gradient }}
                      >
                        <div className="card-top">
                          <div className="card-chip"></div>
                          <div className="card-logo">
                            {cardType === "visa" && (
                              <svg
                                viewBox="0 0 75 24"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <path
                                  d="M18.669 0.832H13.235L8.465 16.516L5.201 3.844H4.037L0.017 16.516L0 0.832H-4.252V23.168H1.724L6.965 6.788L10.337 23.168H14.549L22.913 0.832H18.669Z"
                                  fill="white"
                                />
                                <path
                                  d="M33.845 0.832L29.593 23.168H34.193L38.445 0.832H33.845ZM28.291 0.832L24.899 12.188L24.413 9.476C24.035 7.424 23.003 4.904 20.891 3.596L24.053 0.832H28.291Z"
                                  fill="white"
                                />
                                <path
                                  d="M52.013 23.168H56.549L52.505 0.832H48.017L40.085 23.168H44.685L45.893 19.988H50.849L52.013 23.168ZM48.371 15.932L50.081 11.234L51.221 15.932H48.371Z"
                                  fill="white"
                                />
                                <path
                                  d="M63.921 7.196C63.921 4.544 61.425 2.816 58.377 2.816C55.773 2.816 54.015 4.388 54.015 6.464C54.015 7.916 54.993 9.08 55.971 9.692L54.333 13.916L53.169 16.516L52.335 15.932L54.765 10.844C54.387 10.58 54.129 10.22 54.015 9.812C53.499 7.844 54.729 6.092 56.637 6.092C57.921 6.092 58.755 6.716 58.755 7.64C58.755 8.3 58.239 8.78 57.591 9.08L57.213 9.236C56.331 9.596 56.025 10.052 56.025 10.664C56.025 10.844 56.061 11.444 57.213 11.444H58.281L59.115 9.188H63.297L62.001 12.572C61.449 14.12 60.165 14.744 58.755 14.744C56.331 14.744 54.837 13.22 54.837 11.132C54.837 9.812 55.353 8.708 56.331 8.228L57.921 7.484C58.569 7.196 58.827 6.812 58.827 6.332C58.827 5.252 57.759 4.604 56.565 4.604C54.927 4.604 53.715 5.756 53.565 7.424L49.317 6.644C49.677 3.044 52.881 0.832 57.381 0.832C61.461 0.832 63.921 3.116 63.921 7.196Z"
                                  fill="white"
                                />
                                <path
                                  d="M74.14 0.832L69.888 23.168H74.488L78.74 0.832H74.14Z"
                                  fill="white"
                                />
                              </svg>
                            )}
                            {cardType === "mastercard" && (
                              <svg
                                viewBox="0 0 38 24"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <path
                                  d="M34.608 12.001C34.608 18.628 18.628 24.001 12 24.001C5.372 24.001 0 18.628 0 12.001C0 5.372 5.372 0 12 0C18.628 0 34.608 5.372 34.608 12.001Z"
                                  fill="#EB001B"
                                />
                                <path
                                  d="M38 12.001C38 5.372 32.628 0 26 0C19.372 0 13.392 5.372 13.392 12.001C13.392 18.628 19.372 24.001 26 24.001C32.628 24.001 38 18.628 38 12.001Z"
                                  fill="#F79E1B"
                                />
                                <path
                                  d="M21.986 11.996C21.986 8.946 22.38 6.04 22.95 3.383C19.537 1.22 15.82 0 12 0C5.372 0 0 5.372 0 12s5.372 12 12 12c3.82 0 7.537-1.22 10.95-3.383c-.57-2.657-.964-5.563-.964-8.621Z"
                                  fill="#FF5F00"
                                />
                              </svg>
                            )}
                          </div>
                        </div>
                        <div className="card-number">
                          {formatCardNumber(card.cardNumber)}
                        </div>
                        <div className="card-details">
                          <div className="card-info">
                            <div className="card-holder">
                              <span className="detail-label">Card Holder</span>
                              <span>{card.cardholderName}</span>
                            </div>
                            <div className="card-expiry">
                              <span className="detail-label">Expires</span>
                              <span>
                                {card.expiryMonth}/{card.expiryYear}
                              </span>
                            </div>
                          </div>
                          <div className="card-action-buttons">
                            <button
                              className="edit-card-btn"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleEditCard(card);
                              }}
                              aria-label="Edit card"
                            >
                              <svg
                                width="20"
                                height="20"
                                viewBox="0 0 24 24"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <path
                                  d="M11 4H4C3.46957 4 2.96086 4.21071 2.58579 4.58579C2.21071 4.96086 2 5.46957 2 6V20C2 20.5304 2.21071 21.0391 2.58579 21.4142C2.96086 21.7893 3.46957 22 4 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V13"
                                  stroke="currentColor"
                                  strokeWidth="2"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                />
                                <path
                                  d="M18.5 2.5C18.8978 2.10218 19.4374 1.87868 20 1.87868C20.5626 1.87868 21.1022 2.10218 21.5 2.5C21.8978 2.89782 22.1213 3.43739 22.1213 4C22.1213 4.56261 21.8978 5.10218 21.5 5.5L12 15L8 16L9 12L18.5 2.5Z"
                                  stroke="currentColor"
                                  strokeWidth="2"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                />
                              </svg>
                            </button>
                            <button
                              className="delete-card-btn"
                              onClick={(e) => {
                                e.stopPropagation();
                                confirmDeleteCard(card.id);
                              }}
                              aria-label="Delete card"
                            >
                              <svg
                                width="20"
                                height="20"
                                viewBox="0 0 24 24"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <path
                                  d="M3 6H5H21"
                                  stroke="currentColor"
                                  strokeWidth="2"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                />
                                <path
                                  d="M8 6V4C8 3.46957 8.21071 2.96086 8.58579 2.58579C8.96086 2.21071 9.46957 2 10 2H14C14.5304 2 15.0391 2.21071 15.4142 2.58579C15.7893 2.96086 16 3.46957 16 4V6M19 6V20C19 20.5304 18.7893 21.0391 18.4142 21.4142C18.0391 21.7893 17.5304 22 17 22H7C6.46957 22 5.96086 21.7893 5.58579 21.4142C5.21071 21.0391 5 20.5304 5 20V6H19Z"
                                  stroke="currentColor"
                                  strokeWidth="2"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                />
                              </svg>
                            </button>
                          </div>
                        </div>
                      </div>
                      <div
                        className="credit-card-back"
                        style={{ background: card.gradient }}
                      >
                        <div className="magnetic-stripe"></div>
                        <div className="signature-cvv-container">
                          <div className="signature-panel"></div>
                          <div className="cvv-box">
                            <span>
                              {cvvVisible[card.id] ? card.cvv : "•••"}
                            </span>
                            <button
                              className="icon-btn"
                              onClick={(e) => toggleCvvVisibility(e, card.id)}
                              aria-label="Toggle CVV visibility"
                            >
                              {cvvVisible[card.id] ? (
                                <svg
                                  width="20"
                                  height="20"
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  xmlns="http://www.w3.org/2000/svg"
                                  stroke="currentColor"
                                  strokeWidth="2"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                >
                                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                                  <line x1="1" y1="1" x2="23" y2="23" />
                                </svg>
                              ) : (
                                <svg
                                  width="20"
                                  height="20"
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  xmlns="http://www.w3.org/2000/svg"
                                  stroke="currentColor"
                                  strokeWidth="2"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                >
                                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                                  <circle cx="12" cy="12" r="3" />
                                </svg>
                              )}
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

const Tools = () => {
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [passwordLength, setPasswordLength] = useState(16);
  const [includeUppercase, setIncludeUppercase] = useState(true);
  const [includeLowercase, setIncludeLowercase] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);

  const [strengthPassword, setStrengthPassword] = useState("");
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,
    feedback: "",
  });
  const toast = useToast();

  const generatePassword = () => {
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const numbers = "0123456789";
    const symbols = "!@#$%^&*()_+~`|}{[]:;?><,./-=";

    let charset = "";
    if (includeUppercase) charset += upper;
    if (includeLowercase) charset += lower;
    if (includeNumbers) charset += numbers;
    if (includeSymbols) charset += symbols;

    if (charset === "") {
      setGeneratedPassword("");
      return;
    }

    let newPassword = "";
    for (let i = 0; i < passwordLength; i++) {
      newPassword += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    setGeneratedPassword(newPassword);
  };

  useEffect(() => {
    generatePassword();
  }, [
    passwordLength,
    includeUppercase,
    includeLowercase,
    includeNumbers,
    includeSymbols,
  ]);

  const handleCopy = () => {
    navigator.clipboard.writeText(generatedPassword).then(() => {
      toast.addToast("Password copied to clipboard!", "success");
    });
  };

  useEffect(() => {
    const { score, feedback } = checkPasswordStrength(strengthPassword);
    setPasswordStrength({ score, feedback: strengthPassword ? feedback : "" });
  }, [strengthPassword]);

  const strengthMeterClass = () => {
    switch (passwordStrength.score) {
      case 1:
        return "strength-weak";
      case 2:
        return "strength-moderate";
      case 3:
        return "strength-good";
      case 4:
        return "strength-strong";
      case 5:
        return "strength-very-strong";
      default:
        return "";
    }
  };

  return (
    <div className="page-content">
      <div className="tools-container">
        <h2 className="tools-header">Security Tools</h2>
        <div className="tools-grid">
          {/* Password Generator */}
          <div className="card tool-card">
            <div className="card-header">
              <svg
                className="icon"
                style={{ color: "var(--accent-color-green)" }}
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M12 8V12L14.5 14.5"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M15 19L19 15"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M16.5 12H19.5"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M19 9L21 7"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M12 4.5V1.5"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M9 5L7 3"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M7.5 12H4.5"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M5 15L3 17"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              <span>Password Generator</span>
            </div>
            <p className="card-subtitle">Create strong, random passwords.</p>
            <div className="password-display">
              <span className="generated-password">{generatedPassword}</span>
              <button className="copy-btn-tool" onClick={handleCopy}>
                <svg
                  width="20"
                  height="20"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M8 16H6C4.89543 16 4 15.1046 4 14V6C4 4.89543 4.89543 4 6 4H14C15.1046 4 16 4.89543 16 6V8"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <rect
                    x="8"
                    y="8"
                    width="12"
                    height="12"
                    rx="2"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </button>
            </div>
            <div className="generator-options">
              <div className="option-item">
                <label htmlFor="length">
                  Length: <span>{passwordLength}</span>
                </label>
                <input
                  type="range"
                  id="length"
                  min="8"
                  max="64"
                  value={passwordLength}
                  onChange={(e) =>
                    setPasswordLength(parseInt(e.target.value, 10))
                  }
                />
              </div>
              <div className="option-item-checkboxes">
                <div className="checkbox-wrapper">
                  <input
                    type="checkbox"
                    id="uppercase"
                    checked={includeUppercase}
                    onChange={() => setIncludeUppercase(!includeUppercase)}
                  />
                  <label htmlFor="uppercase">Uppercase (A-Z)</label>
                </div>
                <div className="checkbox-wrapper">
                  <input
                    type="checkbox"
                    id="lowercase"
                    checked={includeLowercase}
                    onChange={() => setIncludeLowercase(!includeLowercase)}
                  />
                  <label htmlFor="lowercase">Lowercase (a-z)</label>
                </div>
                <div className="checkbox-wrapper">
                  <input
                    type="checkbox"
                    id="numbers"
                    checked={includeNumbers}
                    onChange={() => setIncludeNumbers(!includeNumbers)}
                  />
                  <label htmlFor="numbers">Numbers (0-9)</label>
                </div>
                <div className="checkbox-wrapper">
                  <input
                    type="checkbox"
                    id="symbols"
                    checked={includeSymbols}
                    onChange={() => setIncludeSymbols(!includeSymbols)}
                  />
                  <label htmlFor="symbols">Symbols (!@#$)</label>
                </div>
              </div>
            </div>
            <button className="btn btn-primary" onClick={generatePassword}>
              Generate New Password
            </button>
          </div>

          {/* Password Strength Checker */}
          <div className="card tool-card">
            <div className="card-header">
              <svg
                className="icon"
                style={{ color: "var(--accent-color-blue)" }}
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M12 22S19 18 19 12V5L12 2L5 5V12C5 18 12 22 12 22Z"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M9 12L11 14L15 10"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              <span>Strength Checker</span>
            </div>
            <p className="card-subtitle">Test the strength of your password.</p>
            <div className="strength-checker">
              <input
                type="text"
                className="strength-input"
                placeholder="Enter a password..."
                value={strengthPassword}
                onChange={(e) => setStrengthPassword(e.target.value)}
              />
              <div className="strength-meter">
                <div
                  className={`strength-bar ${strengthMeterClass()}`}
                  style={{ width: `${passwordStrength.score * 20}%` }}
                ></div>
              </div>
              <p className="strength-feedback">
                {passwordStrength.feedback || " "}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const Backup = () => {
  const loggedInUser = useContext(UserContext);
  const importFileRef = useRef(null);
  const toast = useToast();

  const [sections, setSections] = useState({
    vault: true,
    notes: true,
    cards: true,
  });
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState("export"); // 'export' or 'import'
  const [masterPassword, setMasterPassword] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState("");
  const [fileToImport, setFileToImport] = useState(null);

  const handleCheckboxChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const { name, checked } = event.target;
    setSections((prev) => ({ ...prev, [name]: checked }));
  };

  // --- UTILITY FUNCTIONS ---
  const arrayBufferToBase64 = (buffer) => {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  };

  const base64ToArrayBuffer = (base64) => {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  };

  const getKey = (password, salt) => {
    const key = CryptoJS.PBKDF2(password, salt, {
      keySize: 256 / 32,
      iterations: 10000,
    });
    return key;
  };

  const encryptBackup = async (data, password) => {
    const salt = CryptoJS.lib.WordArray.random(16);
    const iv = CryptoJS.lib.WordArray.random(16);
    const key = getKey(password, salt);
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), key, {
      iv: iv,
    });

    return {
      salt: salt.toString(CryptoJS.enc.Hex),
      iv: iv.toString(CryptoJS.enc.Hex),
      content: encrypted.toString(),
    };
  };

  const decryptBackup = (encryptedData, password) => {
    try {
      const salt = CryptoJS.enc.Hex.parse(encryptedData.salt);
      const iv = CryptoJS.enc.Hex.parse(encryptedData.iv);
      const key = getKey(password, salt);

      const decrypted = CryptoJS.AES.decrypt(encryptedData.content, key, {
        iv: iv,
      });
      const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);

      if (!decryptedText) {
        throw new Error("Decryption failed. Check master password.");
      }
      return JSON.parse(decryptedText);
    } catch (e) {
      console.error(e);
      throw new Error(
        "Decryption failed. Invalid master password or corrupted file."
      );
    }
  };

  const handleExport = async () => {
    if (!sections.vault && !sections.notes && !sections.cards) {
      toast.addToast("Please select at least one section to export.", "error");
      return;
    }
    setModalMode("export");
    setIsModalOpen(true);
  };

  const handleImport = () => {
    importFileRef.current.click();
  };

  const onFileSelected = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setFileToImport(file);
      setModalMode("import");
      setIsModalOpen(true);
    }
    event.target.value = null;
  };

  const resetModal = () => {
    setIsModalOpen(false);
    setMasterPassword("");
    setError("");
    setIsProcessing(false);
    setFileToImport(null);
  };

  const handleModalSubmit = async () => {
    if (!masterPassword) {
      setError("Master password is required.");
      return;
    }
    setError("");
    setIsProcessing(true);

    if (modalMode === "export") {
      await performExport();
    } else {
      await performImport();
    }
  };

  const performExport = async () => {
    try {
      // FIX: Provide a type for dataToExport to allow adding properties.
      const dataToExport: { vault?: any[]; notes?: any[]; cards?: any[] } = {};
      if (sections.vault) {
        const res = await fetch(`${API_BASE_URL}/vault`, {
          headers: { "X-User-ID": loggedInUser.id },
        });
        dataToExport.vault = await res.json();
      }
      if (sections.notes) {
        const res = await fetch(`${API_BASE_URL}/notes`, {
          headers: { "X-User-ID": loggedInUser.id },
        });
        dataToExport.notes = await res.json();
      }
      if (sections.cards) {
        const res = await fetch(`${API_BASE_URL}/cards`, {
          headers: { "X-User-ID": loggedInUser.id },
        });
        dataToExport.cards = await res.json();
      }

      const backupData = {
        meta: {
          userId: loggedInUser.id,
          username: loggedInUser.username,
          exportDate: new Date().toISOString(),
          version: "1.0.0",
        },
        data: dataToExport,
      };

      const encryptedData = await encryptBackup(backupData, masterPassword);
      const blob = new Blob([JSON.stringify(encryptedData)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const date = new Date().toISOString().slice(0, 10);
      a.download = `localpass_backup_${loggedInUser.username}_${date}.json`;
      a.click();
      URL.revokeObjectURL(url);

      toast.addToast("Export completed successfully!", "success");
      resetModal();
    } catch (e) {
      console.error("Export failed:", e);
      setError("An unexpected error occurred during export.");
      setIsProcessing(false);
    }
  };

  const performImport = async () => {
    if (!fileToImport) return;
    try {
      const encryptedContent = await fileToImport.text();
      const encryptedData = JSON.parse(encryptedContent);
      const decryptedData = decryptBackup(encryptedData, masterPassword);

      const response = await fetch(`${API_BASE_URL}/backup/import`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-User-ID": loggedInUser.id,
        },
        body: JSON.stringify(decryptedData),
      });

      if (response.ok) {
        toast.addToast(
          "Import successful! Data is being refreshed.",
          "success"
        );
        // Consider forcing a reload or re-fetch in all data-heavy components
        setTimeout(() => window.location.reload(), 1500);
        resetModal();
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || "Import failed on the server.");
      }
    } catch (e) {
      console.error("Import failed:", e);
      setError(e.message || "An error occurred during import.");
      setIsProcessing(false);
    }
  };

  return (
    <div className="page-content">
      <div className="backup-container">
        <h2 className="backup-header">Backup & Restore</h2>
        <div className="card backup-card">
          <div className="card-header">
            <svg
              className="icon"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M12 15L12 3"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M16 11L12 15L8 11"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M21 15V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21H5C4.46957 21 3.96086 20.7893 3.58579 20.4142C3.21071 20.0391 3 19.5304 3 19V15"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <span>Create or Restore a Backup</span>
          </div>
          <p className="card-subtitle">
            Export your data to a secure, encrypted file. You can use this file
            to restore your vault on any device. Remember your master password,
            as it's required to decrypt the backup file.
          </p>
          <div className="backup-sections-list">
            <h4>Select data to include in export:</h4>
            <div className="checkbox-wrapper">
              <input
                type="checkbox"
                id="vault"
                name="vault"
                checked={sections.vault}
                onChange={handleCheckboxChange}
              />
              <label htmlFor="vault">Vault (Logins and Passwords)</label>
            </div>
            <div className="checkbox-wrapper">
              <input
                type="checkbox"
                id="notes"
                name="notes"
                checked={sections.notes}
                onChange={handleCheckboxChange}
              />
              <label htmlFor="notes">Secure Notes</label>
            </div>
            <div className="checkbox-wrapper">
              <input
                type="checkbox"
                id="cards"
                name="cards"
                checked={sections.cards}
                onChange={handleCheckboxChange}
              />
              <label htmlFor="cards">Credit Cards</label>
            </div>
          </div>
          <div className="backup-actions">
            <input
              type="file"
              ref={importFileRef}
              style={{ display: "none" }}
              accept=".json"
              onChange={onFileSelected}
            />
            <button className="btn btn-secondary" onClick={handleImport}>
              Import from File
            </button>
            <button className="btn btn-primary" onClick={handleExport}>
              Export to File
            </button>
          </div>
        </div>

        {isModalOpen && (
          <div className="modal-overlay visible">
            <div className="modal-content">
              <button
                className="modal-close-btn"
                onClick={resetModal}
                disabled={isProcessing}
              >
                &times;
              </button>
              <h2>
                {modalMode === "export"
                  ? "Encrypt Your Backup"
                  : "Decrypt Your Backup"}
              </h2>
              <p className="backup-modal-subtitle">
                This master password is used to encrypt or decrypt your backup
                file. It is not your account password unless you choose to use
                the same one.
              </p>
              <div className="modal-form-group">
                <label htmlFor="masterPassword">
                  Master Password for Backup
                </label>
                <input
                  type="password"
                  id="masterPassword"
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  disabled={isProcessing}
                />
              </div>
              <div className="backup-error-text">{error}</div>
              <div className="modal-actions">
                <button
                  className="btn btn-secondary"
                  onClick={resetModal}
                  disabled={isProcessing}
                >
                  Cancel
                </button>
                <button
                  className="btn btn-primary"
                  onClick={handleModalSubmit}
                  disabled={isProcessing}
                >
                  {isProcessing
                    ? "Processing..."
                    : modalMode === "export"
                    ? "Encrypt & Export"
                    : "Decrypt & Import"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const Sidebar = ({ onLogout, isCollapsed, setCollapsed }) => {
  const location = useLocation();
  const loggedInUser = useContext(UserContext);
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 768);

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 768);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const getInitials = (name) => {
    if (!name) return "??";
    const names = name.split(" ");
    if (names.length > 1) {
      return names[0][0] + names[names.length - 1][0];
    }
    return name.substring(0, 2);
  };

  const navItems = [
    {
      path: "/",
      label: "Dashboard",
      icon: (
        <svg
          className="sidebar-item-icon"
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M10 3H3V10H10V3Z"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M21 3H14V10H21V3Z"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M21 14H14V21H21V14Z"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M10 14H3V21H10V14Z"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      ),
    },
    {
      path: "/vault",
      label: "Vault",
      icon: (
        <svg
          className="sidebar-item-icon"
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M7 11V7C7 5.67392 7.52678 4.40215 8.46447 3.46447C9.40215 2.52678 10.6739 2 12 2C13.3261 2 14.5979 2.52678 15.5355 3.46447C16.4732 4.40215 17 5.67392 17 7V11"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M4 22H20V11H4V22Z"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      ),
    },
    {
      path: "/secure-notes",
      label: "Secure Notes",
      icon: (
        <svg
          className="sidebar-item-icon"
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M14 2V8H20"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      ),
    },
    {
      path: "/credit-cards",
      label: "Credit Cards",
      icon: (
        <svg
          className="sidebar-item-icon"
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M22 8V6C22 4.89543 21.1046 4 20 4H4C2.89543 4 2 4.89543 2 6V18C2 19.1046 2.89543 20 4 20H20C21.1046 20 22 19.1046 22 18V16"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M2 10H22"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M7 15H9"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      ),
    },
    {
      path: "/tools",
      label: "Tools",
      icon: (
        <svg
          className="sidebar-item-icon"
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M7 7L17 17"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M16 17H19V20"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M5.00003 11C5.00003 7.13401 8.13404 4 12 4C13.8192 4 15.4678 4.64375 16.7088 5.70875L18.2913 4.29125C16.6343 2.86625 14.4312 2 12 2C7.02947 2 3.00003 6.02944 3.00003 11"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M19 13C19 16.866 15.866 20 12 20C10.1808 20 8.53225 19.3563 7.29125 18.2912L5.70875 19.7087C7.36575 21.1337 9.56881 22 12 22C16.9706 22 21 17.9706 21 13"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      ),
    },
    {
      path: "/backup",
      label: "Backup",
      icon: (
        <svg
          className="sidebar-item-icon"
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M21 15V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21H5C4.46957 21 3.96086 20.7893 3.58579 20.4142C3.21071 20.0391 3 19.5304 3 19V15"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M17 8L12 3L7 8"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M12 3V15"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      ),
    },
  ];

  const bottomNavItems = [
    {
      action: onLogout,
      label: "Logout",
      icon: (
        <svg
          className="sidebar-item-icon"
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M15 3H19C19.5304 3 20.0391 3.21071 20.4142 3.58579C20.7893 3.96086 21 4.46957 21 5V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21H15"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M10 17L15 12L10 7"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M15 12H3"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      ),
    },
  ];

  return (
    <aside className={`sidebar ${isCollapsed && !isMobile ? "collapsed" : ""}`}>
      <div className="sidebar-header-container">
        <h1 className="sidebar-header">LocalPass</h1>
        <button
          className="sidebar-toggle-btn"
          onClick={() => setCollapsed(!isCollapsed)}
        >
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M3 12H21"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M3 6H21"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M3 18H21"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <Link
            to={item.path}
            key={item.path}
            className={`sidebar-item ${
              location.pathname === item.path ? "active" : ""
            }`}
          >
            {item.icon}
            <span>{item.label}</span>
          </Link>
        ))}
      </nav>

      <div className="sidebar-footer">
        {bottomNavItems.map((item) => (
          <button
            onClick={item.action}
            key={item.label}
            className="sidebar-item"
          >
            {item.icon}
            <span>{item.label}</span>
          </button>
        ))}
        <div className="user-profile">
          <div className="user-avatar">
            {getInitials(loggedInUser?.username)}
          </div>
          <div className="user-info">
            <div className="user-name">{loggedInUser?.username}</div>
          </div>
        </div>
      </div>
    </aside>
  );
};

const UserSelectionScreen = ({ setView, setSelectedUserForLogin, onLogin }) => {
  const [users, setUsers] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [menuVisible, setMenuVisible] = useState(null);
  const toast = useToast();
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [userToDelete, setUserToDelete] = useState(null);
  const menuRef = useRef(null);

  const fetchUsers = async () => {
    try {
      setIsLoading(true);
      const response = await fetch(`${API_BASE_URL}/users`);
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      const data = await response.json();
      setUsers(data);
    } catch (error) {
      console.error("Failed to fetch users:", error);
      toast.addToast("Could not fetch user profiles.", "error");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setMenuVisible(null);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleSelectUser = (user) => {
    setSelectedUserForLogin(user);
    setView("login");
  };

  const confirmDelete = (user) => {
    setUserToDelete(user);
    setIsConfirmOpen(true);
    setMenuVisible(null);
  };

  const handleDeleteUser = async () => {
    if (!userToDelete) return;
    try {
      const response = await fetch(`${API_BASE_URL}/users/${userToDelete.id}`, {
        method: "DELETE",
      });
      if (response.ok) {
        toast.addToast(`User "${userToDelete.username}" deleted.`, "success");
        fetchUsers(); // Refresh the list
      } else {
        throw new Error("Failed to delete user.");
      }
    } catch (error) {
      console.error("Failed to delete user:", error);
      toast.addToast("Failed to delete user.", "error");
    } finally {
      setIsConfirmOpen(false);
      setUserToDelete(null);
    }
  };

  const getInitials = (name) => {
    if (!name) return "??";
    const names = name.split(" ");
    if (names.length > 1) {
      return names[0][0] + names[names.length - 1][0];
    }
    return name.substring(0, 2);
  };

  return (
    <div className="user-selection-container">
      <ConfirmationModal
        isOpen={isConfirmOpen}
        onClose={() => setIsConfirmOpen(false)}
        onConfirm={handleDeleteUser}
        title="Delete Account?"
      >
        Are you sure you want to permanently delete the account for "
        {userToDelete?.username}"? All associated data (vault items, notes,
        cards) will be lost forever. This action cannot be undone.
      </ConfirmationModal>

      <div className="user-selection-header">
        <h1 className="user-selection-title">Who's using LocalPass?</h1>
        <p className="user-selection-subtitle">
          Select your profile to continue or create a new one.
        </p>
      </div>
      <div className="profiles-grid">
        {isLoading ? (
          <p>Loading profiles...</p>
        ) : (
          users.map((user, index) => (
            <div
              className="profile-card"
              key={user.id}
              style={{ animationDelay: `${index * 50}ms` }}
            >
              <div
                onClick={() => handleSelectUser(user)}
                style={{ cursor: "pointer", display: "contents" }}
              >
                <div
                  className="profile-avatar"
                  style={{
                    backgroundColor:
                      cardGradients[index % cardGradients.length],
                  }}
                >
                  {getInitials(user.username)}
                </div>
                <div className="profile-name">{user.username}</div>
              </div>
              <button
                className="profile-card-menu-btn"
                onClick={() =>
                  setMenuVisible(menuVisible === user.id ? null : user.id)
                }
              >
                <svg
                  width="20"
                  height="20"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <circle
                    cx="12"
                    cy="12"
                    r="1"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                  <circle
                    cx="12"
                    cy="5"
                    r="1"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                  <circle
                    cx="12"
                    cy="19"
                    r="1"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                </svg>
              </button>
              {menuVisible === user.id && (
                <div className="profile-card-menu" ref={menuRef}>
                  <button
                    className="profile-card-menu-item delete"
                    onClick={() => confirmDelete(user)}
                  >
                    Delete Account
                  </button>
                </div>
              )}
            </div>
          ))
        )}
        <div
          className="profile-card add-profile"
          onClick={() => setView("register")}
          style={{ animationDelay: `${users.length * 50}ms` }}
        >
          <div className="add-profile-icon-wrapper">
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M12 5V19"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M5 12H19"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <div className="profile-name">Add Profile</div>
        </div>
      </div>
    </div>
  );
};

const LoginScreen = ({ selectedUser, onLogin, setView }) => {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isShaking, setIsShaking] = useState(false);
  const toast = useToast();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const response = await fetch(`${API_BASE_URL}/users/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: selectedUser.username, password }),
      });
      const data = await response.json();
      if (response.ok) {
        onLogin(data);
        toast.addToast(`Welcome back, ${data.username}!`, "success");
      } else {
        setError(data.error || "Login failed.");
        setIsShaking(true);
        setTimeout(() => setIsShaking(false), 500);
      }
    } catch (err) {
      setError("Failed to connect to the server.");
      setIsShaking(true);
      setTimeout(() => setIsShaking(false), 500);
    }
  };

  const getInitials = (name) => {
    if (!name) return "??";
    const names = name.split(" ");
    if (names.length > 1) return names[0][0] + names[names.length - 1][0];
    return name.substring(0, 2);
  };

  return (
    <div className="auth-page-container">
      <h1 className="auth-logo">
        Local<span>Pass</span>
      </h1>
      <div className={`auth-form-card ${isShaking ? "shake" : ""}`}>
        <button
          onClick={() => setView("user-selection")}
          className="auth-back-btn"
          aria-label="Go back to user selection"
        >
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M15 18L9 12L15 6"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
        <div className="auth-login-user-info">
          <div className="user-avatar">
            {getInitials(selectedUser.username)}
          </div>
          <div className="user-name">{selectedUser.username}</div>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="auth-form-group">
            <input
              type="password"
              className="auth-input"
              placeholder="Master Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <div className="form-error">{error}</div>
          <button type="submit" className="auth-primary-btn">
            Unlock
          </button>
          <div className="auth-actions">
            <button
              type="button"
              onClick={() => setView("user-selection")}
              className="auth-secondary-link"
            >
              Not you?
            </button>
            <button
              type="button"
              onClick={() => setView("forgot-password")}
              className="auth-secondary-link"
            >
              Forgot Password?
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const RegisterScreen = ({ setView }) => {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    username: "",
    password: "",
    confirmPassword: "",
    question1: securityQuestions[0],
    answer1: "",
    question2: securityQuestions[1],
    answer2: "",
  });
  const [error, setError] = useState("");
  const toast = useToast();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleNext = (e) => {
    e.preventDefault();
    setError("");
    if (!formData.username || !formData.password) {
      return setError("Username and password are required.");
    }
    if (formData.password !== formData.confirmPassword) {
      return setError("Passwords do not match.");
    }
    const strength = checkPasswordStrength(formData.password);
    if (strength.score < 3) {
      return setError(
        `Password is too ${strength.feedback}. Please choose a stronger one.`
      );
    }
    setStep(2);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!formData.answer1 || !formData.answer2) {
      return setError("Please answer both security questions.");
    }
    if (formData.question1 === formData.question2) {
      return setError("Please select two different security questions.");
    }
    try {
      const response = await fetch(`${API_BASE_URL}/users/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (response.ok) {
        toast.addToast("Account created successfully!", "success");
        setView("user-selection");
      } else {
        setError(data.error || "Registration failed.");
      }
    } catch (err) {
      setError("Failed to connect to the server.");
    }
  };

  return (
    <div className="register-container">
      <div className="register-sidebar">
        <h1 className="auth-logo">
          Local<span>Pass</span>
        </h1>
        <div className="register-step-indicator">
          <div className={`step-indicator-item ${step === 1 ? "active" : ""}`}>
            <div className="step-indicator-number">1</div>
            <div className="step-indicator-info">
              <h4>Step 1/2</h4>
              <p>Create Your Account</p>
            </div>
          </div>
          <div className={`step-indicator-item ${step === 2 ? "active" : ""}`}>
            <div className="step-indicator-number">2</div>
            <div className="step-indicator-info">
              <h4>Step 2/2</h4>
              <p>Security Questions</p>
            </div>
          </div>
        </div>
        <div className="register-sidebar-footer">
          <button
            onClick={() => setView("user-selection")}
            className="auth-secondary-link"
          >
            Already have an account?
          </button>
        </div>
      </div>
      <div className="register-content">
        <div className="register-form-wrapper">
          {step === 1 && (
            <form onSubmit={handleNext}>
              <h2>Create your Master Password</h2>
              <p className="auth-form-subtitle">
                This password unlocks your vault. Make sure it's strong and
                something you can remember.
              </p>
              <div className="auth-form-group">
                <label>Username</label>
                <input
                  type="text"
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                  className="auth-input"
                  required
                />
              </div>
              <div className="auth-form-group">
                <label>Master Password</label>
                <input
                  type="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  className="auth-input"
                  required
                />
              </div>
              <div className="auth-form-group">
                <label>Confirm Master Password</label>
                <input
                  type="password"
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  className="auth-input"
                  required
                />
              </div>
              <div className="form-error">{error}</div>
              <div className="auth-actions">
                <button type="submit" className="auth-primary-btn">
                  Continue
                </button>
              </div>
            </form>
          )}
          {step === 2 && (
            <form onSubmit={handleSubmit}>
              <h2>Set Up Account Recovery</h2>
              <p className="auth-form-subtitle">
                These questions will help you recover your account if you forget
                your master password.
              </p>
              <div className="auth-form-group">
                <label>Question 1</label>
                <select
                  name="question1"
                  value={formData.question1}
                  onChange={handleChange}
                  className="auth-select"
                  required
                >
                  {securityQuestions.map((q) => (
                    <option key={q} value={q}>
                      {q}
                    </option>
                  ))}
                </select>
              </div>
              <div className="auth-form-group">
                <input
                  type="text"
                  name="answer1"
                  placeholder="Your Answer"
                  value={formData.answer1}
                  onChange={handleChange}
                  className="auth-input"
                  required
                />
              </div>
              <div className="auth-form-group">
                <label>Question 2</label>
                <select
                  name="question2"
                  value={formData.question2}
                  onChange={handleChange}
                  className="auth-select"
                  required
                >
                  {securityQuestions.map((q) => (
                    <option key={q} value={q}>
                      {q}
                    </option>
                  ))}
                </select>
              </div>
              <div className="auth-form-group">
                <input
                  type="text"
                  name="answer2"
                  placeholder="Your Answer"
                  value={formData.answer2}
                  onChange={handleChange}
                  className="auth-input"
                  required
                />
              </div>
              <div className="form-error">{error}</div>
              <div className="auth-actions">
                <button
                  type="button"
                  className="auth-secondary-link"
                  onClick={() => setStep(1)}
                >
                  Back
                </button>
                <button type="submit" className="auth-primary-btn">
                  Create Account
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

const ForgotPasswordScreen = ({ setView }) => {
  // This is a placeholder for the forgot password flow.
  // A full implementation would involve multiple steps and API calls.
  return (
    <div className="auth-page-container">
      <h1 className="auth-logo">
        Local<span>Pass</span>
      </h1>
      <div className="auth-form-card">
        <button
          onClick={() => setView("user-selection")}
          className="auth-back-btn"
          aria-label="Go back to user selection"
        >
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M15 18L9 12L15 6"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
        <h2>Password Recovery</h2>
        <p className="auth-form-subtitle">
          This feature is under construction. Please contact support.
        </p>
        <button
          className="auth-primary-btn"
          onClick={() => setView("user-selection")}
        >
          Back to Login
        </button>
      </div>
    </div>
  );
};

const App = () => {
  const [loggedInUser, setLoggedInUser] = useState(null);
  const [view, setView] = useState("user-selection"); // 'user-selection', 'login', 'register', 'forgot-password'
  const [selectedUserForLogin, setSelectedUserForLogin] = useState(null);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 768);
  const [isMobileSidebarVisible, setIsMobileSidebarVisible] = useState(false);
  const location = useLocation();

  useEffect(() => {
    const user = localStorage.getItem("loggedInUser");
    if (user) {
      setLoggedInUser(JSON.parse(user));
    }
  }, []);

  useEffect(() => {
    setIsMobileSidebarVisible(false); // Close sidebar on route change
  }, [location.pathname]);

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 768);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const handleLogin = (user) => {
    localStorage.setItem("loggedInUser", JSON.stringify(user));
    setLoggedInUser(user);
  };

  const handleLogout = () => {
    localStorage.removeItem("loggedInUser");
    setLoggedInUser(null);
    setView("user-selection");
  };

  if (loggedInUser) {
    return (
      <UserContext.Provider value={loggedInUser}>
        <div style={{ display: "flex", width: "100%" }}>
          {isMobile && (
            <div className="mobile-header">
              <button
                className="sidebar-toggle-btn"
                onClick={() =>
                  setIsMobileSidebarVisible(!isMobileSidebarVisible)
                }
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M3 12H21"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M3 6H21"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M3 18H21"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </button>
              <div className="mobile-header-title">LocalPass</div>
            </div>
          )}
          <Sidebar
            onLogout={handleLogout}
            isCollapsed={isSidebarCollapsed}
            setCollapsed={setIsSidebarCollapsed}
          />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/vault" element={<VaultCarousel />} />
              <Route path="/secure-notes" element={<SecureNotes />} />
              <Route path="/credit-cards" element={<CreditCards />} />
              <Route path="/tools" element={<Tools />} />
              <Route path="/backup" element={<Backup />} />
              <Route
                path="/settings"
                element={
                  <div className="page-content">
                    <div className="settings-container">
                      <h2>Settings</h2>
                      <p>Settings page is under construction.</p>
                    </div>
                  </div>
                }
              />
            </Routes>
          </main>
        </div>
      </UserContext.Provider>
    );
  }

  switch (view) {
    case "login":
      return (
        <LoginScreen
          selectedUser={selectedUserForLogin}
          onLogin={handleLogin}
          setView={setView}
        />
      );
    case "register":
      return <RegisterScreen setView={setView} />;
    case "forgot-password":
      return <ForgotPasswordScreen setView={setView} />;
    case "user-selection":
    default:
      return (
        <UserSelectionScreen
          setView={setView}
          setSelectedUserForLogin={setSelectedUserForLogin}
          onLogin={handleLogin}
        />
      );
  }
};

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <ToastProvider>
      <HashRouter>
        <App />
      </HashRouter>
    </ToastProvider>
  </React.StrictMode>
);
