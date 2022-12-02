package control

const Socket = "/tmp/wag.sock"

type RegistrationResult struct {
	Token    string
	Username string
}
