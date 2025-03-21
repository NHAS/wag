package acls

import "slices"

type Acl struct {
	Mfa   []string `json:",omitempty"`
	Allow []string `json:",omitempty"`
	Deny  []string `json:",omitempty"`
}

func (a *Acl) Equals(b *Acl) bool {
	if a == nil && b == nil {
		return false
	}

	if a == b {
		return true
	}

	return slices.Equal(a.Mfa, b.Mfa) &&
		slices.Equal(a.Allow, b.Allow) &&
		slices.Equal(a.Deny, b.Deny)

}
