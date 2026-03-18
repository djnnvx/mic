package fingerprint_test

import (
	"strings"
	"testing"

	utls "github.com/bogdanfinn/utls"
	"github.com/djnnvx/mic/fingerprint"
)

const knownJA4 = "t13d1516h2_8daaf6152771_02713d6af862"

func TestLookup_Known(t *testing.T) {
	id, ok := fingerprint.Lookup(knownJA4)
	if !ok {
		t.Fatalf("Lookup(%q) returned false; expected true", knownJA4)
	}
	if id.Str() != utls.HelloChrome_131.Str() {
		t.Errorf("Lookup(%q) = %v; want HelloChrome_131", knownJA4, id)
	}
}

func TestLookup_Unknown(t *testing.T) {
	_, ok := fingerprint.Lookup("unknown_hash_that_does_not_exist")
	if ok {
		t.Fatal("Lookup with unknown hash returned true; expected false")
	}
}

func TestNewTLS_Happy(t *testing.T) {
	fp, err := fingerprint.NewTLS(knownJA4)
	if err != nil {
		t.Fatalf("NewTLS(%q) returned error: %v", knownJA4, err)
	}
	if fp == nil {
		t.Fatal("NewTLS returned nil fingerprint")
	}
}

func TestNewTLS_Error(t *testing.T) {
	_, err := fingerprint.NewTLS("not_a_real_ja4_hash")
	if err == nil {
		t.Fatal("NewTLS with unknown hash returned nil error; expected error")
	}
}

func TestName_ContainsJA4(t *testing.T) {
	fp, err := fingerprint.NewTLS(knownJA4)
	if err != nil {
		t.Fatalf("NewTLS: %v", err)
	}
	name := fp.Name()
	if !strings.Contains(name, knownJA4) {
		t.Errorf("Name() = %q; does not contain JA4 hash %q", name, knownJA4)
	}
}

func TestTable_MinEntries(t *testing.T) {
	if len(fingerprint.Table) < 5 {
		t.Errorf("Table has %d entries; want at least 5", len(fingerprint.Table))
	}
}
