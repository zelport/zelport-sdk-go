package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestAdministrationCatalogAndOpen(t *testing.T) {
	r := Record{Version: 1, Group: string(bytes.Repeat([]byte("a"), 64)), DeviceID: ID(), Hostname: "desktop.example.test", PublicKey: RandomNonce(), Sequence: 1, IssuedAt: time.Now().Unix(), Port: 8080}
	r.ExpiresAt = r.IssuedAt + 60
	admin := Service{ID: ID(), Domain: r.DeviceID + ".zelport.localhost", Kind: Administration}
	r.Services = []Service{admin}
	b, e := CanonicalRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseCanonicalRecord(b, time.Now())
	if e != nil || got.Services[0] != admin {
		t.Fatalf("roundtrip: %v", e)
	}
	if _, e = r.Authority(admin.ID); e != nil {
		t.Fatal(e)
	}
	r.Services = append(r.Services, Service{ID: ID(), Domain: "app.localhost", Kind: Application})
	if _, e = CanonicalRecord(r); e == nil {
		t.Fatal("unpublished application accepted")
	}
	r.Services = []Service{admin, admin}
	if _, e = CanonicalRecord(r); e == nil {
		t.Fatal("duplicate admin accepted")
	}
	r.Services = []Service{admin}
	for _, version := range []int{0, 2, 3} {
		r.Version = version
		if _, e = CanonicalRecord(r); e == nil {
			t.Fatalf("version %d accepted", version)
		}
	}
	for _, authority := range []string{"evil.test:8080", "foo.zelport.localhost.evil:8080", "user@foo.zelport.localhost:8080", "foo.zelport.localhost:0"} {
		if (OpenRequest{Kind: Administration, ServiceID: admin.ID, Authority: admin.Domain + ":8080", Admin: &AdminOpen{Authority: authority}}).Validate() == nil {
			t.Fatal("bad authority", authority)
		}
	}
	if (OpenRequest{Kind: Application, ServiceID: ID(), Authority: "app.localhost:8080", Admin: &AdminOpen{Authority: admin.Domain + ":8080"}}).Validate() == nil {
		t.Fatal("application accepted admin context")
	}
}

func TestAdministrationRejectsInvalidKindsAndLinks(t *testing.T) {
	id := ID()
	authority := id + ".zelport.localhost:8080"
	for _, kind := range []string{"", "unknown"} {
		if (OpenRequest{Kind: kind, ServiceID: ID(), Authority: authority}).Validate() == nil {
			t.Fatal("invalid kind accepted", kind)
		}
	}
	for _, links := range [][]ServiceLink{
		{{ServiceID: ID(), URL: "https://service.localhost:8080"}},
		{{ServiceID: ID(), URL: "http://service.localhost:9000"}},
		{{ServiceID: ID(), URL: "http://service.localhost:8080/private"}},
		{{ServiceID: ID(), URL: "http://service.localhost:8080/?key=x"}},
		{{ServiceID: id, URL: "http://a.localhost:8080"}, {ServiceID: id, URL: "http://b.localhost:8080"}},
		make([]ServiceLink, 257),
	} {
		if (OpenRequest{Kind: Administration, ServiceID: ID(), Authority: authority, Admin: &AdminOpen{Authority: authority, ServiceLinks: links}}).Validate() == nil {
			t.Fatal("invalid service links accepted", links)
		}
	}
}
