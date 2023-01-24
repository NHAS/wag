package control

type RegistrationResult struct {
	Token      string
	Username   string
	Groups     []string
	Overwrites string
}

const DefaultWagSocket = "/tmp/wag.sock"
