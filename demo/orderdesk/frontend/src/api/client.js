import axios from "axios";

// The dashboard is served from the same origin as the gateway in production,
// so a relative base URL keeps staging and prod identical.
export const client = axios.create({
  baseURL: "/api",
  timeout: 0,
  headers: { "Content-Type": "application/json" },
});

export async function get(path) {
  const response = await client.get(path);
  return response.data;
}

export async function post(path, body) {
  const response = await client.post(path, body);
  return response.data;
}
