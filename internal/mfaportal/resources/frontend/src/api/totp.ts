import { client, type TOTPDetailsDTO, type TOTPRequestDTO, type GenericResponseDTO, type MFARequest, MFARequestTypes } from ".";

export function getTotpDetails(): Promise<TOTPDetailsDTO> {
  return client.get("/api/totp").then((res) => res.data);
}

export function authoriseTotp(code: TOTPRequestDTO, attempt_register: boolean): Promise<GenericResponseDTO> {
  const data: MFARequest = {
    type: MFARequestTypes.Totp,
    data: code,
    is_registration: attempt_register,
  }
  return client.get("/api/authorise").then((res) => res.data);
}
