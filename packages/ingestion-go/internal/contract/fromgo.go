package contract

import (
	"encoding/json"
	"fmt"
)

// FromGo converts a JSON-marshalable Go value into a *Value by
// marshaling and strictly re-parsing it, so server-generated events obey
// exactly the same rules as client submissions.
func FromGo(v any) (*Value, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	pv, perr := Parse(b)
	if perr != nil {
		return nil, fmt.Errorf("%s", perr.Error())
	}
	if pv.Kind == Null {
		return nil, nil
	}
	return pv, nil
}

// MustFromGo panics on error (for literals in server code).
func MustFromGo(v any) *Value {
	x, err := FromGo(v)
	if err != nil {
		panic(err)
	}
	return x
}
