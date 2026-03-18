package fingerprint_test

import (
	"testing"

	utls "github.com/bogdanfinn/utls"
	"github.com/djnnvx/mic/fingerprint"
)

func TestByName_Happy(t *testing.T) {
	fp, err := fingerprint.ByName("chrome-120")
	if err != nil {
		t.Fatalf("ByName(%q) returned error: %v", "chrome-120", err)
	}
	if fp == nil {
		t.Fatal("ByName returned nil fingerprint")
	}
}

func TestByName_Error(t *testing.T) {
	_, err := fingerprint.ByName("not-a-real-profile")
	if err == nil {
		t.Fatal("ByName with unknown name returned nil error; expected error")
	}
}

func TestName_ReturnsProfile(t *testing.T) {
	fp, err := fingerprint.ByName("chrome-120")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	if fp.Name() != "chrome-120" {
		t.Errorf("Name() = %q; want %q", fp.Name(), "chrome-120")
	}
}

func TestLookup_Known(t *testing.T) {
	id, ok := fingerprint.Lookup("t13d1516h2_8daaf6152771_02713d6af862")
	if !ok {
		t.Fatal("Lookup returned false for known Chrome 120 JA4 hash")
	}
	if id.Str() != utls.HelloChrome_131.Str() {
		t.Errorf("Lookup returned %v; want HelloChrome_131", id)
	}
}

func TestLookup_Unknown(t *testing.T) {
	_, ok := fingerprint.Lookup("unknown_hash_that_does_not_exist")
	if ok {
		t.Fatal("Lookup with unknown hash returned true; expected false")
	}
}

func TestNameTable_HasExpectedProfiles(t *testing.T) {
	expected := []string{"chrome-120", "chrome-120-pq", "firefox-120", "safari-16", "edge-106"}
	for _, name := range expected {
		if _, ok := fingerprint.NameTable[name]; !ok {
			t.Errorf("NameTable missing profile %q", name)
		}
	}
}
