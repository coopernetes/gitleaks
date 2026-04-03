package sources

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// collectFragments drives GitDiffReader.Fragments and returns every yielded Fragment.
func collectFragments(t *testing.T, diff string) []Fragment {
	t.Helper()
	var fragments []Fragment
	r := &GitDiffReader{Reader: strings.NewReader(diff)}
	err := r.Fragments(context.Background(), func(f Fragment, _ error) error {
		fragments = append(fragments, f)
		return nil
	})
	require.NoError(t, err)
	return fragments
}

// ---------------------------------------------------------------------------
// Test diffs
// ---------------------------------------------------------------------------

// A plain git diff adding a new file with two added lines.
const testGitDiffSingleFile = `diff --git a/cmd/app.go b/cmd/app.go
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/cmd/app.go
@@ -0,0 +1,2 @@
+package main
+// a comment
`

// A diff for an existing file where the hunk starts at line 5 (not line 1).
const testGitDiffStartAtLine5 = `diff --git a/config/settings.go b/config/settings.go
index abc1234..def5678 100644
--- a/config/settings.go
+++ b/config/settings.go
@@ -5,3 +5,4 @@
 "fmt"
 "os"
+const secret = "hunter2"
 )
`

// A diff touching two separate files.
const testGitDiffTwoFiles = `diff --git a/a.go b/a.go
index abc1234..def5678 100644
--- a/a.go
+++ b/a.go
@@ -1,1 +1,2 @@
 package main
+// added to a.go
diff --git a/b.go b/b.go
index abc1234..def5678 100644
--- a/b.go
+++ b/b.go
@@ -1,1 +1,2 @@
 package main
+// added to b.go
`

// A diff that only deletes a file (no added lines).
const testGitDiffDeleted = `diff --git a/removed.go b/removed.go
deleted file mode 100644
index abc1234..0000000
--- a/removed.go
+++ /dev/null
@@ -1,3 +0,0 @@
-package main
-
-func main() {}
`

// A binary file diff.
const testGitDiffBinary = `diff --git a/assets/logo.png b/assets/logo.png
index abc1234..def5678 100644
Binary files a/assets/logo.png and b/assets/logo.png differ
`

// A single-file diff with two separate @@ hunks.
const testGitDiffTwoHunks = `diff --git a/main.go b/main.go
index abc1234..def5678 100644
--- a/main.go
+++ b/main.go
@@ -1,3 +1,4 @@
 package main
+// first hunk addition
 
 import "fmt"
@@ -10,3 +11,4 @@
 
 func main() {
+	// second hunk addition
 }
`

// A diff mixing removed and added lines. Only added lines should appear in Raw.
const testGitDiffMixedOperations = `diff --git a/ctx.go b/ctx.go
index abc1234..def5678 100644
--- a/ctx.go
+++ b/ctx.go
@@ -1,3 +1,3 @@
 package main
-// removed line
+// added line
 func main() {}
`

// A git-log-p style diff with a commit patch header.
const testGitDiffWithPatchHeader = `commit deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
Author: Jane Doe <jane@example.com>
Date:   Mon Jan 1 00:00:00 2024 +0000

    Add configuration file

diff --git a/config.yaml b/config.yaml
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/config.yaml
@@ -0,0 +1,2 @@
+host: localhost
+port: 8080
`

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

func TestGitDiffReader_SingleFileAddsFragment(t *testing.T) {
	frags := collectFragments(t, testGitDiffSingleFile)

	require.Len(t, frags, 1)
	assert.Equal(t, "cmd/app.go", frags[0].FilePath)
	assert.Equal(t, 1, frags[0].StartLine)
	assert.Contains(t, frags[0].Raw, "package main")
	assert.Contains(t, frags[0].Raw, "// a comment")
}

// TestGitDiffReader_StartLinePreservedFromHunkHeader verifies that the
// fragment's StartLine reflects the hunk's +newStart value, not always 1.
// This is the primary value of GitDiffReader over plain stdin scanning.
func TestGitDiffReader_StartLinePreservedFromHunkHeader(t *testing.T) {
	frags := collectFragments(t, testGitDiffStartAtLine5)

	require.Len(t, frags, 1)
	assert.Equal(t, "config/settings.go", frags[0].FilePath)
	assert.Equal(t, 5, frags[0].StartLine, "hunk header says +5, so StartLine should be 5")
	assert.Contains(t, frags[0].Raw, `const secret = "hunter2"`)
}

func TestGitDiffReader_MultipleFiles(t *testing.T) {
	frags := collectFragments(t, testGitDiffTwoFiles)

	require.Len(t, frags, 2)
	paths := []string{frags[0].FilePath, frags[1].FilePath}
	assert.ElementsMatch(t, []string{"a.go", "b.go"}, paths)
}

func TestGitDiffReader_SkipsDeletedFile(t *testing.T) {
	frags := collectFragments(t, testGitDiffDeleted)
	assert.Empty(t, frags, "deleted files should produce no fragments")
}

func TestGitDiffReader_SkipsBinaryFile(t *testing.T) {
	frags := collectFragments(t, testGitDiffBinary)
	assert.Empty(t, frags, "binary files should produce no fragments")
}

func TestGitDiffReader_EmptyInput(t *testing.T) {
	frags := collectFragments(t, "")
	assert.Empty(t, frags)
}

// TestGitDiffReader_TwoHunksProduceTwoFragments ensures that each @@ section
// becomes a separate fragment with its own StartLine.
func TestGitDiffReader_TwoHunksProduceTwoFragments(t *testing.T) {
	frags := collectFragments(t, testGitDiffTwoHunks)

	require.Len(t, frags, 2)
	// Both fragments belong to the same file.
	assert.Equal(t, "main.go", frags[0].FilePath)
	assert.Equal(t, "main.go", frags[1].FilePath)
	// StartLine comes from the hunk headers: +1 and +11.
	assert.Equal(t, 1, frags[0].StartLine)
	assert.Equal(t, 11, frags[1].StartLine)
	// Raw contains only the added content of each hunk.
	assert.Contains(t, frags[0].Raw, "// first hunk addition")
	assert.Contains(t, frags[1].Raw, "// second hunk addition")
}

// TestGitDiffReader_OnlyAddedLinesInRaw confirms that context lines (" ")
// and removed lines ("-") are not included in the fragment Raw.
func TestGitDiffReader_OnlyAddedLinesInRaw(t *testing.T) {
	frags := collectFragments(t, testGitDiffMixedOperations)

	require.Len(t, frags, 1)
	assert.Contains(t, frags[0].Raw, "// added line")
	assert.NotContains(t, frags[0].Raw, "// removed line", "removed lines must not appear in Raw")
	assert.NotContains(t, frags[0].Raw, "package main", "context lines must not appear in Raw")
	assert.NotContains(t, frags[0].Raw, "func main", "context lines must not appear in Raw")
}

// TestGitDiffReader_WithPatchHeader verifies that commit metadata is
// populated when parsing git-log-p output (which includes commit headers).
func TestGitDiffReader_WithPatchHeader(t *testing.T) {
	frags := collectFragments(t, testGitDiffWithPatchHeader)

	require.Len(t, frags, 1)
	require.NotNil(t, frags[0].CommitInfo, "commit metadata should be populated from the patch header")
	assert.Equal(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", frags[0].CommitInfo.SHA)
	assert.Equal(t, frags[0].CommitInfo.SHA, frags[0].CommitSHA)
	// Remote must never be nil — the detect layer dereferences it unconditionally.
	assert.NotNil(t, frags[0].CommitInfo.Remote, "Remote must be non-nil to prevent nil dereference in detect layer")
}

// TestGitDiffReader_WithpatchHeaderAuthor verifies that author fields are
// populated when a patch header with Author: line is present.
func TestGitDiffReader_WithPatchHeaderAuthor(t *testing.T) {
	frags := collectFragments(t, testGitDiffWithPatchHeader)

	require.Len(t, frags, 1)
	require.NotNil(t, frags[0].CommitInfo)
	assert.Equal(t, "Jane Doe", frags[0].CommitInfo.AuthorName)
	assert.Equal(t, "jane@example.com", frags[0].CommitInfo.AuthorEmail)
}

// TestGitDiffReader_WithoutPatchHeader confirms that CommitInfo is nil for a
// plain `git diff` output (no commit headers).
func TestGitDiffReader_WithoutPatchHeader_CommitInfoIsNil(t *testing.T) {
	frags := collectFragments(t, testGitDiffSingleFile)

	require.Len(t, frags, 1)
	assert.Nil(t, frags[0].CommitInfo, "plain git diff has no commit metadata; CommitInfo should be nil")
}

// TestGitDiffReader_YieldErrorStopsIteration verifies that an error returned
// from the yield function is propagated immediately and iteration stops.
func TestGitDiffReader_YieldErrorStopsIteration(t *testing.T) {
	sentinel := errors.New("stop iterating")
	count := 0

	r := &GitDiffReader{Reader: strings.NewReader(testGitDiffTwoFiles)}
	err := r.Fragments(context.Background(), func(_ Fragment, _ error) error {
		count++
		return sentinel
	})

	assert.Equal(t, sentinel, err, "error from yield should be propagated")
	assert.Equal(t, 1, count, "iteration should stop after the first yield error")
}

// TestGitDiffReader_ContextCancellationRespected verifies that a cancelled
// context causes Fragments to return without panicking.
func TestGitDiffReader_ContextCancellationRespected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling Fragments

	r := &GitDiffReader{Reader: strings.NewReader(testGitDiffTwoFiles)}
	err := r.Fragments(ctx, func(_ Fragment, _ error) error {
		return nil
	})

	// The context is already done when we enter the loop; either the channel
	// case or the ctx.Done case may win in the select. Both outcomes are valid —
	// what matters is that the call returns and does not panic.
	assert.True(t, err == nil || err == context.Canceled,
		"expected nil or context.Canceled, got: %v", err)
}

// TestGitDiffReader_FilePathStrippedOfPrefix verifies that go-gitdiff strips
// the "b/" prefix from the file path, giving clean paths in findings.
func TestGitDiffReader_FilePathStrippedOfPrefix(t *testing.T) {
	frags := collectFragments(t, testGitDiffSingleFile)

	require.Len(t, frags, 1)
	assert.Equal(t, "cmd/app.go", frags[0].FilePath,
		`FilePath should not contain the "b/" prefix from the diff header`)
}
