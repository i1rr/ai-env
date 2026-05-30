package scanners

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/workspace"
)

// TestBuiltIn_DetectsCommonFakeSecrets pins plan 06 step 10: the
// built-in pattern scanner produces high-confidence, export-blocking
// findings for the documented provider-format API keys, PEM-style
// private key headers, and .env-style assignments. Each row is a real
// fake secret (no live key shape) so the assertion is about the
// scanner behavior, not the secret content.
func TestBuiltIn_DetectsCommonFakeSecrets(t *testing.T) {
	type want struct {
		fileName string
		kind     string
		pattern  string
	}

	type row struct {
		name     string
		file     string
		content  string
		expected []want
	}

	cases := []row{
		{
			name:    "anthropic api key",
			file:    "anthropic.txt",
			content: "API_KEY=sk-ant-AAAAAAAAAAAAAAAAAAAA1234567890\n",
			expected: []want{{
				fileName: "anthropic.txt",
				kind:     "api_key",
				pattern:  "Anthropic sk-ant- prefix",
			}},
		},
		{
			name:    "openai sk- key",
			file:    "openai.txt",
			content: "token = sk-proj-AAAAAAAAAAAAAAAAAAAA12345\n",
			expected: []want{{
				fileName: "openai.txt",
				kind:     "api_key",
				pattern:  "OpenAI sk- prefix",
			}},
		},
		{
			name:    "github personal access token",
			file:    "github.txt",
			content: "token: ghp_AAAAAAAAAAAAAAAAAAAA12345678901234\n",
			expected: []want{{
				fileName: "github.txt",
				kind:     "api_key",
				pattern:  "GitHub personal access token (ghp_)",
			}},
		},
		{
			name:    "aws access key id",
			file:    "aws.txt",
			content: "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n",
			expected: []want{
				{
					fileName: "aws.txt",
					kind:     "api_key",
					pattern:  "AWS access key ID (AKIA)",
				},
				{
					fileName: "aws.txt",
					kind:     "env_assignment",
					pattern:  "Secret-shaped env assignment",
				},
			},
		},
		{
			name:    "google cloud api key",
			file:    "gcp.txt",
			content: "key=AIzaSyA1234567890abcdefghijklmnopqrstuv\n",
			expected: []want{{
				fileName: "gcp.txt",
				kind:     "api_key",
				pattern:  "Google Cloud API key (AIza)",
			}},
		},
		{
			name:    "slack token",
			file:    "slack.txt",
			content: "slack: xoxb-1234567890-AAAAAAAAAAAA-bbbbbbbb\n",
			expected: []want{{
				fileName: "slack.txt",
				kind:     "api_key",
				pattern:  "Slack token (xox)",
			}},
		},
		{
			name:    "stripe key",
			file:    "stripe.txt",
			content: "stripe = sk_live_AAAAAAAAAAAAAAAAAAAA1234\n",
			expected: []want{{
				fileName: "stripe.txt",
				kind:     "api_key",
				pattern:  "Stripe key",
			}},
		},
		{
			name:    "rsa private key header",
			file:    "id_rsa",
			content: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
			expected: []want{{
				fileName: "id_rsa",
				kind:     "private_key",
				pattern:  "BEGIN RSA PRIVATE KEY",
			}},
		},
		{
			name:    "openssh private key header",
			file:    "id_ed25519",
			content: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkt\n",
			expected: []want{{
				fileName: "id_ed25519",
				kind:     "private_key",
				pattern:  "BEGIN OPENSSH PRIVATE KEY",
			}},
		},
		{
			name:    "env secret assignment",
			file:    ".env",
			content: "DATABASE_PASSWORD=supersecretvalue123\n",
			expected: []want{{
				fileName: ".env",
				kind:     "env_assignment",
				pattern:  "Secret-shaped env assignment",
			}},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ws := t.TempDir()
			abs := filepath.Join(ws, tc.file)
			if err := os.WriteFile(abs, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			b, err := NewBuiltIn(Config{})
			if err != nil {
				t.Fatalf("NewBuiltIn: %v", err)
			}

			diff := workspace.DiffResult{
				Files: []workspace.FileDiff{
					{Path: tc.file, Change: workspace.ChangeAdded},
				},
			}
			res, err := b.RunBuiltIn(ws, diff)
			if err != nil {
				t.Fatalf("RunBuiltIn: %v", err)
			}

			if res.Scanner != "built-in-patterns" {
				t.Fatalf("Scanner=%q, want built-in-patterns", res.Scanner)
			}

			for _, w := range tc.expected {
				if !hasFinding(res.Findings, w.fileName, w.kind, w.pattern) {
					t.Fatalf("missing finding kind=%s pattern=%s file=%s; got %+v", w.kind, w.pattern, w.fileName, res.Findings)
				}
			}

			for _, f := range res.Findings {
				if f.Confidence != ConfidenceHigh {
					t.Fatalf("finding %s confidence=%s, want %s", f.ID, f.Confidence, ConfidenceHigh)
				}
				if !f.BlocksExport {
					t.Fatalf("finding %s BlocksExport=false, want true", f.ID)
				}
				if f.EntropyOnly {
					t.Fatalf("finding %s EntropyOnly=true, want false", f.ID)
				}
				if f.File == "" || f.Line == 0 {
					t.Fatalf("finding %s missing File/Line: %+v", f.ID, f)
				}
				if !strings.HasPrefix(f.ID, "finding_") {
					t.Fatalf("finding ID %q does not match finding_NNN convention", f.ID)
				}
			}
		})
	}
}

// TestBuiltIn_AllowlistSuppressesFinding pins the inline allowlist
// channel: a line carrying the documented "ai-env-scan-ignore" comment
// is excluded from both the pattern matcher and the entropy analyzer
// so committed fixtures do not re-trip the scanner on every run.
func TestBuiltIn_AllowlistSuppressesFinding(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "fixture.txt"),
		[]byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE # ai-env-scan-ignore\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	b, err := NewBuiltIn(Config{})
	if err != nil {
		t.Fatalf("NewBuiltIn: %v", err)
	}
	res, err := b.RunBuiltIn(ws, workspace.DiffResult{
		Files: []workspace.FileDiff{{Path: "fixture.txt", Change: workspace.ChangeAdded}},
	})
	if err != nil {
		t.Fatalf("RunBuiltIn: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings on allowlisted line, got %+v", res.Findings)
	}
}

// TestBuiltIn_BinaryFilesSkipped pins the binary skip path: files
// whose first 512 bytes contain a NUL byte are not scanned. Without
// this guard, compiled artifacts dropped into the diff would produce
// noise findings.
func TestBuiltIn_BinaryFilesSkipped(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "blob.bin"),
		[]byte{0x00, 0x01, 0x02, 'A', 'K', 'I', 'A', 'I', 'O', 'S', 'F', 'O', 'D', 'N', 'N', '7', 'E', 'X', 'A', 'M', 'P', 'L', 'E'}, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	b, err := NewBuiltIn(Config{})
	if err != nil {
		t.Fatalf("NewBuiltIn: %v", err)
	}
	res, err := b.RunBuiltIn(ws, workspace.DiffResult{
		Files: []workspace.FileDiff{{Path: "blob.bin", Change: workspace.ChangeAdded}},
	})
	if err != nil {
		t.Fatalf("RunBuiltIn: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings on binary file, got %+v", res.Findings)
	}
}

// hasFinding checks whether the given findings slice contains an entry
// matching the file, kind, and pattern. Used by the table-driven
// secret-detection test so the assertion site stays readable.
func hasFinding(findings []Finding, file, kind, pattern string) bool {
	for _, f := range findings {
		if f.File == file && f.Type == kind && f.Pattern == pattern {
			return true
		}
	}
	return false
}
