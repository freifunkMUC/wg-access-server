package resolvconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNameservers(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "empty file",
			content: "",
			want:    nil,
		},
		{
			name:    "a plain resolv.conf",
			content: "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
			want:    []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:    "order is preserved",
			content: "nameserver 8.8.8.8\nnameserver 1.1.1.1\n",
			want:    []string{"8.8.8.8", "1.1.1.1"},
		},
		{
			name:    "IPv4 and IPv6 are both returned",
			content: "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n",
			want:    []string{"1.1.1.1", "2606:4700:4700::1111"},
		},
		{
			name:    "IPv6 addresses are normalised",
			content: "nameserver 2606:4700:4700:0000:0000:0000:0000:1111\n",
			want:    []string{"2606:4700:4700::1111"},
		},
		{
			name:    "hash comments are ignored",
			content: "# nameserver 9.9.9.9\nnameserver 1.1.1.1\n",
			want:    []string{"1.1.1.1"},
		},
		{
			name:    "semicolon comments are ignored",
			content: "; nameserver 9.9.9.9\nnameserver 1.1.1.1\n",
			want:    []string{"1.1.1.1"},
		},
		{
			name:    "other directives are ignored",
			content: "search example.org\noptions ndots:2\ndomain example.org\nnameserver 1.1.1.1\n",
			want:    []string{"1.1.1.1"},
		},
		{
			name:    "leading and repeated whitespace is tolerated",
			content: "   nameserver\t 1.1.1.1  \n\n\nnameserver   8.8.8.8\n",
			want:    []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:    "a nameserver without an address is skipped",
			content: "nameserver\nnameserver 1.1.1.1\n",
			want:    []string{"1.1.1.1"},
		},
		{
			name:    "an unparsable address is skipped",
			content: "nameserver not-an-ip\nnameserver 1.1.1.1\n",
			want:    []string{"1.1.1.1"},
		},
		{
			name:    "a missing trailing newline still yields the entry",
			content: "nameserver 1.1.1.1",
			want:    []string{"1.1.1.1"},
		},
		{
			name:    "CRLF line endings are tolerated",
			content: "nameserver 1.1.1.1\r\nnameserver 8.8.8.8\r\n",
			want:    []string{"1.1.1.1", "8.8.8.8"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNameservers([]byte(tt.content))
			if !equal(got, tt.want) {
				t.Errorf("parseNameservers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNameserversFromSystemdResolved(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("the stub alone redirects to the systemd file", func(t *testing.T) {
		primary := write("stub-only", "nameserver 127.0.0.53\n")
		systemd := write("systemd-real", "nameserver 9.9.9.9\nnameserver 1.1.1.1\n")

		got := nameserversFrom(primary, systemd)
		if want := []string{"9.9.9.9", "1.1.1.1"}; !equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("the stub is never handed out when the systemd file is missing", func(t *testing.T) {
		primary := write("stub-only-2", "nameserver 127.0.0.53\n")

		if got := nameserversFrom(primary, filepath.Join(dir, "does-not-exist")); got != nil {
			t.Errorf("got %v, want nil - the stub resolver is useless as an upstream", got)
		}
	})

	t.Run("the stub alongside a real server is left alone", func(t *testing.T) {
		primary := write("stub-plus", "nameserver 127.0.0.53\nnameserver 1.1.1.1\n")
		systemd := write("systemd-unused", "nameserver 9.9.9.9\n")

		got := nameserversFrom(primary, systemd)
		if want := []string{"127.0.0.53", "1.1.1.1"}; !equal(got, want) {
			t.Errorf("got %v, want %v - only a lone stub means systemd-resolved", got, want)
		}
	})

	t.Run("another loopback address is not treated as the stub", func(t *testing.T) {
		primary := write("other-loopback", "nameserver 127.0.0.1\n")
		systemd := write("systemd-unused-2", "nameserver 9.9.9.9\n")

		got := nameserversFrom(primary, systemd)
		if want := []string{"127.0.0.1"}; !equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an unreadable resolv.conf yields nothing", func(t *testing.T) {
		if got := nameserversFrom(filepath.Join(dir, "nope"), filepath.Join(dir, "nope2")); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
