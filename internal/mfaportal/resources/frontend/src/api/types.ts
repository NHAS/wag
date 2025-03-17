export interface MFAMethod {
  friendly_name: string;
  method: string;
}

export interface MFAMethod {
	method: string
	friendly_name: string
}

export interface UserInfoDTO {
  has_registered: boolean;
  default_mfa: string;
  available_mfa_methods: MFAMethod[];
  username: string;
  is_locked: boolean;
  is_authorized: boolean;
  helpmail: string;
}

export interface ChallengeAuthorisationDTO {
  challenge: string;
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
  password: string
}
