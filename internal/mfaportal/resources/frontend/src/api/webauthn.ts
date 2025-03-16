import {
  client,
  type AuthResponse,
  type MFARequest,
  MFARequestTypes,
} from ".";

export function getRegistrationWebauthnDetails(): Promise<CredentialCreationOptions> {
  return client.get("/api/webauthn/register").then((res) => res.data);
}

export function getAuthorisationWebauthnDetails(): Promise<CredentialRequestOptions> {
  return client.get("/api/webauthn/authorise").then((res) => res.data);
}

export function authoriseWebauthn(
  details: CredentialCreationOptions | CredentialRequestOptions,
  attempt_register: boolean,
): Promise<AuthResponse> {
  const data: MFARequest = {
    type: MFARequestTypes.Webauthn,
    data: details,
    is_registration: attempt_register,
  };
  return client.post("", data).then((res) => res.data);
}
