import { client, type UserInfoDTO } from ".";

export function apiGetInfo(): Promise<UserInfoDTO> {
  return client.get("/api/userinfo").then((res) => res.data);
}
