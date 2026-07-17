package main

import "testing"

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		config: Config{
			ProductCode: demoProductCode,
		},
	}
}
