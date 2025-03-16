import {
  client,
  type AuthResponse,
} from ".";

export function getRegistrationWebauthnDetails(): Promise<CredentialCreationOptions> {
  return client.get("/api/webauthn/register").then((res) => res.data);
}

export function getAuthorisationWebauthnDetails(): Promise<CredentialRequestOptions> {
  return client.get("/api/webauthn/authorise").then((res) => res.data);
}
