import { client, type AuthResponse } from ".";

export function getRegistrationWebauthnDetails(): Promise<AuthResponse> {
  return client.get("/api/webauthn/register/").then((res) => res.data);
}

export function finaliseWebauthnRegistration(
  cred: PublicKeyCredential,
): Promise<AuthResponse> {
  return client
    .post("/api/webauthn/register/", cred.toJSON())
    .then((res) => res.data);
}

export function getAuthorisationWebauthnDetails(): Promise<AuthResponse> {
  return client.get("/api/webauthn/authorise/").then((res) => res.data);
}

export function authoriseWebAuthn(
  cred: PublicKeyCredential,
): Promise<AuthResponse> {
  return client
    .post("/api/webauthn/authorise/", cred.toJSON())
    .then((res) => res.data);
}
