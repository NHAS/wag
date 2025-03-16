import {
  client,
  type AuthResponse,
  type PamAuthRequestDTO,
} from ".";

export function authorisePam(
  password: string,
): Promise<AuthResponse> {
  const data: PamAuthRequestDTO = {
    password:password,
  };
  return client.post("/api/pam/authorise", data).then((res) => res.data).catch(e => {
    if (e.status != 200) {
      if (e.response.data.status !== undefined && e.response.data.status == "error") {
        throw new Error(e.response.data.error)
      }
    }

    throw e
  });
}

export function registerPam(
  password: string,
): Promise<AuthResponse> {
  const data: PamAuthRequestDTO = {
    password:password,
  };
  return client.post("/api/pam/register", data).then((res) => res.data).catch(e => {
    if (e.status != 200) {
      if (e.response.data.status !== undefined && e.response.data.status == "error") {
        throw new Error(e.response.data.error)
      }
    }

    throw e
  });
}
