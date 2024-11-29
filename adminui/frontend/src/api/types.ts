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

export interface EditDevicesDTO {
  action: DeviceEditActions
  addresses: string[]
}

export enum DeviceEditActions {
  Lock = 'lock',
  Unlock = 'unlock'
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

export enum UserEditActions {
  Lock = 'lock',
  Unlock = 'unlock',
  ResetMFA = 'resetMFA'
}

export interface EditUsersDTO {
  action: UserEditActions
  usernames: string[]
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

export interface EventErrorDTO {
  node_id: string
  error_id: string

  failed_event_data: string
  error: string
  time: string
}

export interface EventState {
  current: string
  previous: string
}

export interface GeneralEvent {
  type: string
  key: string
  time: string
  state: EventState
}

export interface ClusterEvents {
  events: GeneralEvent[]
  errors: EventErrorDTO[]
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

export interface ChangePasswordRequestDTO {
  current_password: string
  new_password: string
}

export interface GenericResponseDTO {
  message: string
  success: boolean
}

export interface GeneralSettingsResponseDTO {
  help_mail: string
  external_address: string
  dns: string[]
  wireguard_config_filename: string
  check_updates: boolean
}

export interface OidcResponseDTO {
  issuer: string
  client_secret: string
  client_id: string
  group_claim_name: string
  device_username_claim: string
}

export interface PamResponseDTO {
  service_name: string
}

export interface LoginSettingsResponseDTO {
  session_inactivity_timeout_minutes: number
  max_session_lifetime_minutes: number
  lockout: number

  default_mfa_method: string
  enabled_mfa_methods: string[]

  issuer: string

  oidc: OidcResponseDTO
  pam: PamResponseDTO
}

export interface AcmeDetailsDTO {
  provider_url: string
  email: string
  api_token_set: boolean
}

export interface MFAMethodDTO {
  friendly_name: string
  method: string
}

export interface AdminUsersDTO {
  user_type: string
  username: string
  attempts: number
  date_added: string
  last_login: string
  ip: string
  change: boolean
  oidc_guid: string
}

export interface WgDeviceDTO {
  rx: number
  tx: number
  public_key: string
  address: string
  last_endpoint: string
  last_handshake_time: string
}

export interface FwDevice {
  last_packet_timestamp: string
  expiry: string
  ip: string
  authorized: boolean
  associated_node: string
}

export interface FirewallRulesDTO {
  policies: string[]
  devices: FwDevice[]
  account_locked: boolean
}

export interface FirewallTestRequestDTO {
  address: string
  protocol: string
  target: string
  port: number
}

export interface AclsTestRequestDTO {
  username: string
}

export interface Acl {
  mfa?: string[]
  allow?: string[]
  deny?: string[]
}

export interface AclsTestResponseDTO {
  username: string
  message: string
  success: boolean
  acls: Acl
}

export interface NotificationDTO {
  id: string
  heading: string
  message: string[]
  url: string
  time: string
  color: string
  open_new_tab: boolean
}

export interface TestNotificationsRequestDTO {
  message: string
}

export interface AcknowledgeErrorResponseDTO {
  error_id: string
}

export interface ConfigResponseDTO {
  sso: boolean
  password: boolean
}

export interface NewNodeRequestDTO {
  node_name: string
  connection_url: string
  manager_url: string
}

export interface NewNodeResponseDTO {
  join_token: string
  error_message: string
}

export interface NodeControlRequestDTO {
  node: string
  action: NodeControlActions
}

export enum NodeControlActions {
  Promote = 'promote',
  Drain = 'drain',
  Restore = 'restore',
  Stepdown = 'stepdown',
  Remove = 'remove'
}

export interface WebServerConfigDTO {
  server_name: string
  listen_address: string
  domain: string
  tls: boolean
}
