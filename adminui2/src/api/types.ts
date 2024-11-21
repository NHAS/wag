export interface RuleDTO {
  effects: string
  public_routes: string[]
  mfa_routes: string[]
  deny_routes: string[]
}

export interface RegistrationTokenRequestDTO {
  token: string
  username: string
  groups: string[]
  overwrites: string
  uses: number
}

export interface DeviceDTO {
  owner: string
  is_locked: boolean
  active: boolean
  internal_ip: string
  public_key: string
  last_endpoint: string
}

export interface GetAllDevicesDTO {
  devices: DeviceDTO[]
}

export interface UserDTO {
  devices: string
  username: string
  locked: boolean
  date_added: string
  mfa_type: string
  groups: string[]
}
export interface UsersGetAllResponseDTO {
  users: UserDTO[]
}

export interface GroupDTO {
  group: string
  members: string[]
}

export interface AdminUserDTO {
  user_type: string
  username: string
  attempts: number
  date_added: string
  last_login: string
  ip: string
  change: boolean
  oidc_guid: string
}

export interface AuthLoginResponseDTO {
  success: boolean
  csrfToken: string
  csrfHeader: string
  user: AdminUserDTO
}

export interface ServerInfoDTO {
  subnet: string
  port: number
  public_key: string
  external_address: string
  version: string
}

export interface LogLinesDTO {
  log_lines: string[]
}

export interface EventError {
  node_id: string
  error_id: string

  failed_event_data: string
  error: string
  time: string
}

export interface ClusterEvents {
  events: string[]
  errors: EventError[]
}

export interface ClusterMember {
  id: string
  name: string

  current_node: boolean
  drained: boolean
  witness: boolean
  leader: boolean
  learner: boolean
  version: string
  last_ping: string
  status: string
  peer_urls: string[]
}

export interface GenericResponseDTO {
  message: string
  success: boolean
}
