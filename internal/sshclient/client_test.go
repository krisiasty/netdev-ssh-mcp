package sshclient

import "testing"

func TestValidateKnownHostsPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{
			name: "absolute path is accepted",
			path: "/tmp/known_hosts",
			want: "/tmp/known_hosts",
		},
		{
			name: "absolute path is cleaned",
			path: "/tmp/ssh/../known_hosts",
			want: "/tmp/known_hosts",
		},
		{
			name:    "relative path is rejected",
			path:    "known_hosts",
			wantErr: true,
		},
		{
			name:    "traversal-only relative path is rejected",
			path:    "../../known_hosts",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validateKnownHostsPath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validateKnownHostsPath(%q) error = nil, want error", tt.path)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateKnownHostsPath(%q) error = %v", tt.path, err)
			}
			if got != tt.want {
				t.Fatalf("validateKnownHostsPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
