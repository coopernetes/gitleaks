package sources

import (
	"context"
	"io"

	"github.com/gitleaks/go-gitdiff/gitdiff"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
)

// GitDiffReader is a source that parses a raw git diff from an io.Reader,
// yielding fragments with file paths and line numbers extracted from the diff
// headers. This is useful when piping the output of `git diff` or `git log -p`
// directly into gitleaks, rather than running git commands from within gitleaks.
type GitDiffReader struct {
	// Reader is the source of the raw git diff (e.g. os.Stdin).
	Reader io.Reader
}

// Fragments implements Source. It parses the diff and yields one fragment per
// added hunk per file, preserving the original file path and starting line
// number from the diff metadata.
func (s *GitDiffReader) Fragments(ctx context.Context, yield FragmentsFunc) error {
	diffFilesCh, err := gitdiff.Parse(s.Reader)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case gitdiffFile, open := <-diffFilesCh:
			if !open {
				return nil
			}

			if gitdiffFile == nil || gitdiffFile.IsDelete || gitdiffFile.IsBinary {
				continue
			}

			var commitInfo *CommitInfo
			if gitdiffFile.PatchHeader != nil {
				commitInfo = &CommitInfo{
					SHA:     gitdiffFile.PatchHeader.SHA,
					Message: gitdiffFile.PatchHeader.Message(),
					Remote:  &RemoteInfo{Platform: scm.NoPlatform},
				}
				if gitdiffFile.PatchHeader.Author != nil {
					commitInfo.AuthorName = gitdiffFile.PatchHeader.Author.Name
					commitInfo.AuthorEmail = gitdiffFile.PatchHeader.Author.Email
				}
			}

			for _, textFragment := range gitdiffFile.TextFragments {
				if textFragment == nil {
					continue
				}

				fragment := Fragment{
					FilePath:   gitdiffFile.NewName,
					Raw:        textFragment.Raw(gitdiff.OpAdd),
					StartLine:  int(textFragment.NewPosition),
					CommitInfo: commitInfo,
				}
				if commitInfo != nil {
					fragment.CommitSHA = commitInfo.SHA
				}

				if err := yield(fragment, nil); err != nil {
					return err
				}
			}
		}
	}
}
