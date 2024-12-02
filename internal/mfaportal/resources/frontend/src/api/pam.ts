import {
  client,
  type GenericResponseDTO,
  type MFARequest,
  MFARequestTypes,
  verifyEndpoint,
  type PamDetailsDTO,
  type PamAuthoriseDTO,
} from ".";

export function getPamDetails(): Promise<PamDetailsDTO> {
  return client.get("/api/pam").then((res) => res.data);
}

export function authorisePam(
  password: PamAuthoriseDTO,
  attempt_register: boolean,
): Promise<GenericResponseDTO> {
  const data: MFARequest = {
    type: MFARequestTypes.Pam,
    data: password,
    is_registration: attempt_register,
  };
  return client.post(verifyEndpoint, data).then((res) => res.data);
}
