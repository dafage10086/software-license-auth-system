package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicGatewayContainsNoProductOrLegacyMarkers(t *testing.T) {
	forbidden := []string{
		strings.Join([]string{"QL", "W10"}, ""),
		strings.Join([]string{"Qing", "Lan"}, ""),
		string([]rune{0x9752, 0x84dd}),
		strings.Join([]string{"159", "195", "58", "181"}, "."),
		strings.Join([]string{"best", "srv.de"}, ""),
		strings.Join([]string{"ql-keygen", "-tunnel"}, ""),
		strings.Join([]string{"@accounts.", "ql.invalid"}, ""),
		"/api/v1/",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || entry.Name() == "public_contract_test.go" {
			continue
		}
		content, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range forbidden {
			if strings.Contains(string(content), marker) {
				t.Fatalf("%s contains a forbidden public marker", entry.Name())
			}
		}
	}
}
