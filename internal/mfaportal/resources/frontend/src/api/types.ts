export interface MFAMethod {
  friendly_name: string;
  method: string;
}

export interface MFAMethod {
	method: string
	friendly_name: string
}

export interface UserInfoDTO {
  version: string

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
  authorisation_time: string
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
  password: string
}
