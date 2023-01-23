package control

type RegistrationResult struct {
	Token    string
	Username string
}

const DefaultWagSocket = "/tmp/wag.sock"
