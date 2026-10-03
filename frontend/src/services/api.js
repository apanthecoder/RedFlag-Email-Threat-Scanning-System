import axios from "axios";

// The one axios instance. Components and pages never import axios
// themselves.
//
// In a production build Flask serves this app from the same address as the
// API, so a relative /api is right. Only the dev server (port 5173) needs
// the full address of Flask on port 5000.
const api = axios.create({
  baseURL:
    import.meta.env.VITE_API_URL || (import.meta.env.DEV ? "http://localhost:5000/api" : "/api"),
  withCredentials: true,
});

// Unwrap the { success, data, error } envelope so callers deal in data.
api.interceptors.response.use(
  (response) => {
    // Binary downloads (the monthly PDF) aren't wrapped in the JSON
    // envelope, so return the whole response.
    if (response.config?.responseType === "blob") return response;
    return response.data?.data;
  },
  async (error) => {
    let envelope = error.response?.data;

    // A failed blob request still has a JSON error body, but as a Blob.
    // Parse it so the user sees the real message and not a generic one.
    if (envelope instanceof Blob) {
      try {
        envelope = JSON.parse(await envelope.text());
      } catch {
        envelope = null;
      }
    }

    if (envelope?.error) {
      return Promise.reject(envelope.error);
    }
    return Promise.reject({
      code: "NETWORK_ERROR",
      message: "Couldn't reach the server.",
    });
  }
);

/**
 * Fetch a file and hand it to the browser as a download.
 *
 * The filename comes from the server's Content-Disposition header when
 * there is one, so the backend decides what the file is called.
 */
export async function downloadFile(path, fallbackFilename) {
  const response = await api.get(path, { responseType: "blob" });

  const disposition = response.headers?.["content-disposition"] || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const filename = match ? match[1] : fallbackFilename;

  const url = URL.createObjectURL(response.data);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export default api;
