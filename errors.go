package networkControl

import (
	"errors"
)

var (
	errAlreadyExists  = errors.New("already exists")
	errConflict       = errors.New("conflict")
	errInvalidArgs    = errors.New("invalid arguments")
	errNotFound       = errors.New("not found")
	errNotImplemented = errors.New("not implemented (yet?)")
)
