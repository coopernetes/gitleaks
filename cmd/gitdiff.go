package cmd

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	rootCmd.AddCommand(gitDiffCmd)
}

var gitDiffCmd = &cobra.Command{
	Use:   "git-diff",
	Short: "detect secrets from a piped git diff",
	Long: `Parse a raw git diff from stdin and detect secrets.

File paths and line numbers are extracted from the diff headers, so findings
are reported against the original source files rather than raw diff offsets.

Example:
  git diff | gitleaks git-diff
  git log -p | gitleaks git-diff
  git diff HEAD~1 HEAD | gitleaks git-diff`,
	Run: runGitDiff,
}

func runGitDiff(cmd *cobra.Command, _ []string) {
	start := time.Now()

	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)
	detector := Detector(cmd, cfg, "")

	exitCode := mustGetIntFlag(cmd, "exit-code")

	findings, err := detector.DetectSource(
		cmd.Context(),
		&sources.GitDiffReader{
			Reader: os.Stdin,
		},
	)

	if err != nil {
		logging.Fatal().Err(err).Msg("failed to scan git diff from stdin")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
