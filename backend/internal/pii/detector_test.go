package pii

import "testing"

func TestScanEmail(t *testing.T) {
	findings := Scan("contact me at user@example.com please")
	if len(findings) == 0 {
		t.Fatal("expected to find email")
	}
	if findings[0].Type != "email" {
		t.Fatalf("expected email, got %s", findings[0].Type)
	}
}

func TestScanPhone(t *testing.T) {
	findings := Scan("call me at 555-123-4567")
	found := false
	for _, f := range findings {
		if f.Type == "phone" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected to find phone")
	}
}

func TestScanCreditCard(t *testing.T) {
	findings := Scan("my card is 4111-1111-1111-1111")
	found := false
	for _, f := range findings {
		if f.Type == "credit_card" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected to find credit_card")
	}
}

func TestScanSSN(t *testing.T) {
	findings := Scan("ssn 123-45-6789")
	found := false
	for _, f := range findings {
		if f.Type == "ssn" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected to find ssn")
	}
}

func TestScanNoPII(t *testing.T) {
	findings := Scan("hello world this is totally fine")
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestScanMultiple(t *testing.T) {
	findings := Scan("email user@test.com and call 555-123-4567")
	types := DetectedTypes(findings)
	if len(types) < 2 {
		t.Fatalf("expected at least 2 types, got %d", len(types))
	}
}

func TestDetectedTypesUnique(t *testing.T) {
	findings := Scan("a@b.com c@d.com")
	types := DetectedTypes(findings)
	if len(types) != 1 {
		t.Fatalf("expected 1 unique type, got %d", len(types))
	}
}
