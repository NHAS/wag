package acls

type Acl struct {
	Mfa   []string `json:",omitempty"`
	Allow []string `json:",omitempty"`
	Deny  []string `json:",omitempty"`
}
