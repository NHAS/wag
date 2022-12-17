package authenticators

type Authenticator func(mfaSecret, username string) error
