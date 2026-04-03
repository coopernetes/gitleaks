package detect

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/sources"
)

// ---------------------------------------------------------------------------
// Test diffs
// ---------------------------------------------------------------------------

// A new-file diff that adds an AWS access key on line 3 of the file.
// The hunk starts at +1, so fragment.StartLine=1.  The key is the 3rd
// added line (0-indexed offset 2), giving finding.StartLine = 1+2 = 3.
const detectTestDiffAwsKey = `diff --git a/deploy/config.go b/deploy/config.go
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/deploy/config.go
@@ -0,0 +1,3 @@
+package main
+
+const awsKey = "AKIALALEMEL33243OKIA"
`

// A diff in which the secret appears in the middle of a file (hunk at +10).
// Two context lines ("-10,2") + one added line ("+10,3") — valid hunk counts.
const detectTestDiffHunkOffset = `diff --git a/internal/cfg.go b/internal/cfg.go
index abc1234..def5678 100644
--- a/internal/cfg.go
+++ b/internal/cfg.go
@@ -10,2 +10,3 @@
 // existing code
+const awsKey = "AKIALALEMEL33243OKIA"
 func init() {}
`

// A diff adding a sha512 integrity hash to package-lock.json.
// This should produce no findings because gitleaks.toml allowlists
// package-lock.json globally.
const detectTestDiffPackageLock = `diff --git a/package-lock.json b/package-lock.json
index abc1234..def5678 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,4 +1,6 @@
 {
+  "integrity": "sha512-7XHNxH7UtZs/SKTJBS9WMRiFuJGbH1amBNWMa9PH1gSIcGgRIzs2SCCXj9EqOlNDqzEIAp6Gq75XJXrv3bBQ==",
+  "resolved": "https://registry.npmjs.org/some-package/-/some-package-1.0.0.tgz",
   "name": "test-app",
   "version": "1.0.0",
   "lockfileVersion": 3
`

// A diff where the secret line has a gitleaks:allow comment.
const detectTestDiffAllowComment = `diff --git a/config.go b/config.go
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/config.go
@@ -0,0 +1 @@
+const key = "AKIALALEMEL33243OKIA" // gitleaks:allow
`

// A diff across two files, each adding a distinct AWS key.
const detectTestDiffTwoFilesWithSecrets = `diff --git a/service/a.go b/service/a.go
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/service/a.go
@@ -0,0 +1 @@
+const keyA = "AKIALALEMEL33243OKIA"
diff --git a/service/b.go b/service/b.go
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/service/b.go
@@ -0,0 +1 @@
+const keyB = "AKIALALEMEL33243OLIA"
`

// A diff that only removes a secret (no additions). Under no circumstances
// should gitleaks flag a line that was deleted from a file.
const detectTestDiffDeletedOnlyLines = `diff --git a/old_creds.go b/old_creds.go
index abc1234..def5678 100644
--- a/old_creds.go
+++ b/old_creds.go
@@ -1,3 +1,2 @@
 package main
-const deletedKey = "AKIALALEMEL33243OKIA"
 func main() {}
`

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

func detectorWithDefaultConfig(t *testing.T) *Detector {
	t.Helper()
	d, err := NewDetectorDefaultConfig()
	require.NoError(t, err)
	return d
}

func detectGitDiff(t *testing.T, diff string) []interface{} {
	t.Helper()
	return nil // unused placeholder; see individual tests below
}

// TestDetectGitDiffReader_ReportsCorrectFile verifies that the File field on
// the finding matches the path extracted from the diff header, not a generic
// "<stdin>" or similar placeholder.
func TestDetectGitDiffReader_ReportsCorrectFile(t *testing.T) {
	d := detectorWithDefaultConfig(t)

	findings, err := d.DetectSource(context.Background(), &sources.GitDiffReader{
		Reader: strings.NewReader(detectTestDiffAwsKey),
	})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "deploy/config.go", findings[0].File)
}

// TestDetectGitDiffReader_ReportsCorrectStartLine verifies that the line number
// is correctly derived from the diff hunk position rather than defaulting to 0
// or 1.  The secret is the 3rd added line in a hunk that starts at +1, so
// finding.StartLine should be 3.
func TestDetectGitDiffReader_ReportsCorrectStartLine(t *testing.T) {
	d := detectorWithDefaultConfig(t)

	findings, err := d.DetectSource(context.Background(), &sources.GitDiffReader{
		Reader: strings.NewReader(detectTestDiffAwsKey),
	})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, 3, findings[0].StartLine,
		"StartLine should reflect position within the file, not within the raw fragment")
}

// TestDetectGitDiffReader_HunkOffsetAppliedToStartLine checks a diff where the
// hunk starts at line 10 (not 1).  The secret is the first added line, so
// finding.StartLine should equal the hunk start (10 + 0 = 10).
func TestDetectGitDiffReader_HunkOffsetAppliedToStartLine(t *testing.T) {
	d := detectorWithDefaultConfig(t)

	findings, err := d.DetectSource(context.Background(), &sources.GitDiffReader{
		Reader: strings.NewReader(detectTestDiffHunkOffset),
	})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "internal/cfg.go", findings[0].File)
	assert.Equal(t, 10, findings[0].StartLine,
		"StartLine should be hunk start (10) + offset within Raw (0) = 10")
}

// TestDetectGitDiffReader_RuleIDPopulated ensures the finding carries the
// correct rule identifier so downstream tooling can filter by rule.
func TestDetectGitDiffReader_RuleIDPopulated(t *testing.T) {
	d := detectorWithDefaultConfig(t)

	findings, err := d.DetectSource(context.Background(), &sources.GitDiffReader{
		Reader: strings.NewReader(detectTestDiffAwsKey),
	})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	// The default config reports AWS access key IDs under the "aws-access-token" rule.
	assert.Equal(t, "aws-access-token", findings[0].RuleID)
	assert.Equal(t, "AKIALALEMEL33243OKIA", findings[0].Secret)
}

// TestDetectGitDiffReader_PackageLockAllowlisted verifies that sha512 integrity
// hashes in package-lock.json do not trigger findings.  gitleaks.toml contains
// a global path allowlist entry for package-lock.json.
func TestDetectGitDiffReader_PackageLockAllowlisted(t *testing.T) {
	d := detectorWithDefaultConfig(t)

	findings, err := d.DetectSource(context.Background(), &sources.GitDiffReader{
		Reader: strings.NewReader(detectTestDiffPackageLock),
	})

	require.NoError(t, err)
	assert.Empty(t, findings, "package-lock.json is globally allowlisted; no findings expected")
}

// TestDetectGitDiffReader_GitleaksAllowCommentSuppressesFinding checks that
// the `// gitleaks:allow` inline annotation works when the input comes from a
// piped diff rather than a direct file scan.
func TestDetectGitDiffReader_GitleaksAllowCommentSuppressesFinding(t *testing.T) {
	d := detectorWithDefaultConfig(t)

	findings, err := d.DetectSource(context.Background(), &sources.GitDiffReader{
		Reader: strings.NewReader(detectTestDiffAllowComment),
	})

	require.NoError(t, err)
	assert.Empty(t, findings, "gitleaks:allow annotation should suppress the finding")
}

// TestDetectGitDiffReader_MultipleFilesFindingsIsolated ensures that when
// multiple files in a single diff each contain a secret, findings are reported
// with the correct per-file path and are not conflated.
func TestDetectGitDiffReader_MultipleFilesFindingsIsolated(t *testing.T) {
	d := detectorWithDefaultConfig(t)

	findings, err := d.DetectSource(context.Background(), &sources.GitDiffReader{
		Reader: strings.NewReader(detectTestDiffTwoFilesWithSecrets),
	})

	require.NoError(t, err)
	require.Len(t, findings, 2)

	files := map[string]bool{}
	for _, f := range findings {
		files[f.File] = true
	}
	assert.True(t, files["service/a.go"], "finding for service/a.go expected")
	assert.True(t, files["service/b.go"], "finding for service/b.go expected")
}

// TestDetectGitDiffReader_NoFindingsForDeletedLines confirms that secrets on
// removed lines ("-" prefix in the diff) are never reported.  Gitleaks should
// only flag secrets being introduced, not ones being removed.
func TestDetectGitDiffReader_NoFindingsForDeletedLines(t *testing.T) {
	d := detectorWithDefaultConfig(t)

	findings, err := d.DetectSource(context.Background(), &sources.GitDiffReader{
		Reader: strings.NewReader(detectTestDiffDeletedOnlyLines),
	})

	require.NoError(t, err)
	assert.Empty(t, findings, "secrets on deleted lines should not be reported")
}

// TestDetectGitDiffReader_EmptyDiff verifies that an empty diff produces no
// findings and no error.
func TestDetectGitDiffReader_EmptyDiff(t *testing.T) {
	d := detectorWithDefaultConfig(t)

	findings, err := d.DetectSource(context.Background(), &sources.GitDiffReader{
		Reader: strings.NewReader(""),
	})

	require.NoError(t, err)
	assert.Empty(t, findings)
}
