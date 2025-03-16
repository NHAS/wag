import axios from "axios";

export const client = axios.create();

export * from "./types";
export * from "./totp";
export * from "./webauthn";
export * from "./pam";

export function logout(): Promise<boolean> {
  return client.post("/api/logout").then((res) => {
    return (res.status === 204)
  });
}
