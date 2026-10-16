package protocol

import (
	"encoding/json"
	"errors"
)

type RelayRoute struct {
	Version                                      int
	Group, ConsumerRoute, ProviderRoute, Session string
}

func (r RelayRoute) Bytes() ([]byte, error) {
	if r.Version != Version || !ValidLocator(r.Group) || !ValidLocator(r.ConsumerRoute) || !ValidLocator(r.ProviderRoute) || r.ConsumerRoute == r.ProviderRoute {
		return nil, errors.New("invalid routing context")
	}
	if _, e := DecodeKey(r.Session); e != nil {
		return nil, e
	}
	return json.Marshal([]any{r.Version, r.Group, r.ConsumerRoute, r.ProviderRoute, r.Session})
}
func ParseRelayRoute(b []byte) (RelayRoute, error) {
	var r RelayRoute
	e := Array(b, &r.Version, &r.Group, &r.ConsumerRoute, &r.ProviderRoute, &r.Session)
	if e == nil {
		_, e = r.Bytes()
	}
	return r, e
}

func (r RelayRoute) MarshalJSON() ([]byte, error) { return r.Bytes() }
func (r *RelayRoute) UnmarshalJSON(b []byte) error {
	v, e := ParseRelayRoute(b)
	if e == nil {
		*r = v
	}
	return e
}
