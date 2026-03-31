package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/bobbydeveaux/guardian/app/internal/report"
	"github.com/bobbydeveaux/guardian/app/internal/scanner"
)

var (
	noOSV     bool
	noSecrets bool
	noSAST    bool
	noColor   bool
	fullScan  bool
)

var rootCmd = &cobra.Command{
	Use:   "guardian",
	Short: "Guardian — local pre-commit security scanner",
	Long: `Guardian scans your staged git changes for:
  • Known CVEs in dependencies (via OSV database)
  • Hardcoded secrets and credentials
  • Code-level security issues (via Claude AI)`,
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Scan staged changes for security issues",
	RunE:  runCheck,
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Guardian as a git pre-commit hook",
	RunE:  runInstall,
}

func runCheck(cmd *cobra.Command, args []string) error {
	if noColor {
		color.NoColor = true
	}

	opts := scanner.Options{
		OSV:     !noOSV,
		Secrets: !noSecrets,
		SAST:    !noSAST,
		Full:    fullScan,
	}

	results, err := scanner.Run(opts)
	if err != nil {
		return err
	}

	if len(results.StagedFiles) == 0 {
		if fullScan {
			fmt.Println("  No tracked files found. Is this a git repository?")
		} else {
			fmt.Println("  No staged files found. Stage your changes first with: git add <files>")
			fmt.Println("  Tip: use --full to scan the entire codebase regardless of staging.")
		}
		return nil
	}

	report.Print(results)
	os.Exit(report.ExitCode(results))
	return nil
}

func runInstall(cmd *cobra.Command, args []string) error {
	// Find the .git/hooks directory
	hookDir := ".git/hooks"
	if _, err := os.Stat(hookDir); os.IsNotExist(err) {
		return fmt.Errorf("not in a git repo root (no .git/hooks found)")
	}

	hookPath := hookDir + "/pre-commit"
	hookScript := `#!/bin/sh
# Guardian pre-commit hook — installed by: guardian install
guardian check
exit $?
`
	if err := os.WriteFile(hookPath, []byte(hookScript), 0755); err != nil {
		return fmt.Errorf("failed to write hook: %w", err)
	}

	color.Green("  ✓ Pre-commit hook installed at %s", hookPath)
	fmt.Println("  Guardian will now scan every commit automatically.")
	fmt.Println("  To skip: git commit --no-verify")
	return nil
}

func main() {
	checkCmd.Flags().BoolVar(&noOSV, "no-osv", false, "Skip OSV dependency vulnerability check")
	checkCmd.Flags().BoolVar(&noSecrets, "no-secrets", false, "Skip secrets detection")
	checkCmd.Flags().BoolVar(&noSAST, "no-sast", false, "Skip Claude AI code analysis")
	checkCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable coloured output")
	checkCmd.Flags().BoolVar(&fullScan, "full", false, "Scan entire tracked codebase, not just staged files")

	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(installCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
