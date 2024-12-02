import axios from "axios";

export const client = axios.create();
export const verifyEndpoint = "/api/mfa/verify";

export * from "./types";
export * from "./totp";
export * from "./webauthn";
export * from "./pam";
