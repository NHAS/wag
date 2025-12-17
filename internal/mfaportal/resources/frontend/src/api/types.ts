export interface MFAMethod {
  friendly_name: string;
  method: string;
}

export interface VersionsDTO {
  web: string;
  wag: string;
}

export interface UserInfoDTO {
  versions: VersionsDTO;

  has_registered: boolean;
  user_mfa_method: string;
  default_mfa: string;
  available_mfa_methods: MFAMethod[];
  username: string;

  account_locked: boolean;
  device_locked: boolean;

  is_authorized: boolean;
  helpmail: string;
}

export interface ChallengeAuthorisationRequestDTO {
  type: string;
  challenge: string;
}

export interface AuthorisationResponseDTO {
  type: string;
  authorisation_time: string;
  challenge: string;
  info: UserInfoDTO;
}

export interface TOTPDetailsDTO {
  image_data: string;
  account_name: string;
  key: string;
}

export interface TOTPRequestDTO {
  code: string;
}

export interface AuthResponse {
  status: string;
  data: any;
  error: string;
}

export interface PamAuthRequestDTO {
  password: string;
}

export interface StatusDTO {
  IsAuthorised: boolean;

  MFA: string[];
  Public: string[];
  Deny: string[];
}
