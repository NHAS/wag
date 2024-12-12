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
  available_mfa_methods: MFAMethod[];
  username: string;
  is_locked: boolean;
  is_authorized: boolean;
  helpmail: string;
}

export interface TOTPDetailsDTO {
  qrcode: string;
  account_name: string;
  key: string;
}

export interface TOTPRequestDTO {
  code: string;
}

export interface GenericResponseDTO {
  message: string;
  success: boolean;
}

export interface MFARequest {
  type: MFARequestTypes;
  data:
    | TOTPRequestDTO
    | CredentialCreationOptions
    | CredentialRequestOptions
    | PamAuthoriseDTO;
  is_registration: boolean;
}

export enum MFARequestTypes {
  Totp = "totp",
  Webauthn = "webauthn",
  Pam = "pam",
}

export interface PamDetailsDTO {
  account_name: string;
}

export interface PamAuthoriseDTO {
  password: string;
}
