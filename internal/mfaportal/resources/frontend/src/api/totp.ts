import {
  client,
  type TOTPDetailsDTO,
  type TOTPRequestDTO,
  type AuthResponse,
} from ".";

export function getTotpDetails(): Promise<TOTPDetailsDTO> {
  return client.post("/api/totp/register/details").then((res) => {
    if (res.status !== 200) {
      throw new Error(`API request failed with status code: ${res.status}`);
    }

    if (res.data.status != "register_details") {
      throw new Error(`API request returned unexpected type "${res.data.status}"`);
    }

    return res.data.data
  });
}

export function registerTotp(
  code: string,
): Promise<AuthResponse> {
  const data: TOTPRequestDTO = {
    code: code,
  };



  return client.post("/api/totp/register/complete", data).then((res) => {
    return res.data
  }).catch(e => {
    if (e.status != 200) {
      if (e.response.data.status !== undefined && e.response.data.status == "error") {
        throw new Error(e.response.data.error)
      }
    }

    throw e
  });
}


export function authoriseTotp(
  code: string,
): Promise<AuthResponse> {
  const data: TOTPRequestDTO = {
    code: code,
  };



  return client.post("/api/totp/authorise", data).then((res) => {
    return res.data
  }).catch(e => {
    if (e.status != 200) {
      if (e.response.data.status !== undefined && e.response.data.status == "error") {
        throw new Error(e.response.data.error)
      }
    }

    throw e
  });
}
