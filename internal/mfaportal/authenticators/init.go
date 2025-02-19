package authenticators

type enable bool

func (e *enable) IsEnabled() bool {
	return bool(*e)
}

func (e *enable) Disable() {
	*e = false
}

func (e *enable) Enable() {
	*e = true
}
