# Wag Control Package

This package is a collection of helper methods to interact with the wag unix socket. 

```go
ctrl = wagctl.NewControlClient("/tmp/wag.sock")

version, err := ctrl.Version()
// handle your errors here

```