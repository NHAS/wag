-- version 5
ALTER TABLE Users ADD mfa_type string DEFAULT "unset" NOT NULL;
UPDATE Users SET mfa_type = "totp";