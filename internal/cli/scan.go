package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/rivan1986/ai-env/internal/config"
	"github.com/rivan1986/ai-env/internal/run"
	"github.com/rivan1986/ai-env/internal/scanners"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// ScanOptions captures the parsed flags + positional argument for
// `ai-env scan`. The CLI wiring layer fills this in and passes it to
// RunScan so the command body has no direct Cobra dependency.
type ScanOptions struct {
	EnvName string

	// RunID, when non-empty, selects a specific historical run as the
	// scan artifact target. Defaults to the env's latest run.
	RunID string

	// Cwd is the working directory the command was invoked from.
	// RunScan walks upward from Cwd looking for the project's .ai-env/
	// directory (mirroring `ai-env diff` / `status` / `report`).
	Cwd string

	Stdout io.Writer
	Stderr io.Writer
}

// RunScan is the entry point used by the Cobra wiring for `ai-env scan`.
// It locates the project's .ai-env/, loads policy, computes the
// workspace diff, runs the built-in scanner plus every available
// external scanner, writes secret-scan.json + dependency-report.json
// to the run directory, and prints a summary.
func RunScan(opts ScanOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env scan: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env scan: %w", err)
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env scan: %w", err)
	}

	info, err := workspace.ReadMetadata(aiEnvDir, opts.EnvName)
	if err != nil {
		return fmt.Errorf("ai-env scan: %w", err)
	}

	matcher, mErr := loadProtectedMatcher(aiEnvDir)
	if mErr != nil {
		return fmt.Errorf("ai-env scan: %w", mErr)
	}

	diff, err := workspace.Diff(aiEnvDir, opts.EnvName, matcher)
	if err != nil {
		return fmt.Errorf("ai-env scan: %w", err)
	}

	cfg, err := loadScannerConfig(aiEnvDir)
	if err != nil {
		return fmt.Errorf("ai-env scan: %w", err)
	}

	runner, err := scanners.NewBuiltIn(cfg)
	if err != nil {
		return fmt.Errorf("ai-env scan: %w", err)
	}

	var summary run.RunSummary
	if opts.RunID != "" {
		summary, err = run.FindRunByID(aiEnvDir, opts.RunID)
	} else {
		summary, err = run.LatestRunForEnv(aiEnvDir, opts.EnvName)
	}
	if err != nil {
		if errors.Is(err, run.ErrNoRuns) {
			return fmt.Errorf("ai-env scan: no run directory for env %q; run the agent at least once before scanning", opts.EnvName)
		}
		return fmt.Errorf("ai-env scan: %w", err)
	}

	builtIn, err := runner.RunBuiltIn(info.Path, diff)
	if err != nil {
		return fmt.Errorf("ai-env scan: built-in scanner: %w", err)
	}
	builtIn.RunID = summary.ID

	external := runner.DiscoverExternal()
	var externalResults []scanners.ScanResult
	var externalErrors []externalError
	for _, e := range external {
		if !e.Available {
			continue
		}
		res, err := runner.RunExternal(e, info.Path)
		if err != nil {
			externalErrors = append(externalErrors, externalError{Name: e.Name, Err: err})
			continue
		}
		res.RunID = summary.ID
		externalResults = append(externalResults, res)
	}

	if err := writeSecretScan(summary.Path, builtIn, externalResults); err != nil {
		return fmt.Errorf("ai-env scan: %w", err)
	}
	if err := writeDependencyReport(summary.Path, external, externalResults); err != nil {
		return fmt.Errorf("ai-env scan: %w", err)
	}

	renderScanSummary(opts.Stdout, opts.Stderr, scanSummary{
		EnvName:         opts.EnvName,
		RunID:           summary.ID,
		RunPath:         summary.Path,
		BuiltIn:         builtIn,
		External:        external,
		ExternalResults: externalResults,
		ExternalErrors:  externalErrors,
	})
	return nil
}

// externalError carries a per-scanner failure so the summary can warn
// the operator without aborting the whole scan.
type externalError struct {
	Name string
	Err  error
}

// scanSummary bundles everything renderScanSummary prints.
type scanSummary struct {
	EnvName         string
	RunID           string
	RunPath         string
	BuiltIn         scanners.ScanResult
	External        []scanners.ExternalScanner
	ExternalResults []scanners.ScanResult
	ExternalErrors  []externalError
}

// loadScannerConfig materializes a scanners.Config from policy.yaml.
// A missing or malformed policy is surfaced as a hard error so the
// operator does not silently get the default scanner when their custom
// patterns failed to load.
func loadScannerConfig(aiEnvDir string) (scanners.Config, error) {
	policyPath := filepath.Join(aiEnvDir, "policy.yaml")
	if _, err := os.Stat(policyPath); err != nil {
		if os.IsNotExist(err) {
			return scanners.Config{}, nil
		}
		return scanners.Config{}, fmt.Errorf("stat policy %s: %w", policyPath, err)
	}
	policy, err := config.LoadPolicy(policyPath)
	if err != nil {
		return scanners.Config{}, err
	}
	return scanners.Config{
		CustomPatterns: policy.Scanners.CustomPatterns,
	}, nil
}

// secretScanFile is the on-disk shape of secret-scan.json. The top
// level holds the built-in result plus any external secret scanner
// (gitleaks) result so the export gate sees one consolidated file.
type secretScanFile struct {
	RunID            string                    `json:"run_id"`
	Scanner          string                    `json:"scanner"`
	Findings         []scanners.Finding        `json:"findings"`
	EntropyWarnings  []scanners.EntropyWarning `json:"entropy_warnings"`
	ScannedAt        string                    `json:"scanned_at"`
	ExternalScanners []scanners.ScanResult     `json:"external_scanners,omitempty"`
}

func writeSecretScan(runPath string, builtIn scanners.ScanResult, external []scanners.ScanResult) error {
	var secretExternals []scanners.ScanResult
	for _, r := range external {
		if r.Scanner == "gitleaks" {
			secretExternals = append(secretExternals, r)
		}
	}
	out := secretScanFile{
		RunID:            builtIn.RunID,
		Scanner:          builtIn.Scanner,
		Findings:         builtIn.Findings,
		EntropyWarnings:  builtIn.EntropyWarnings,
		ScannedAt:        builtIn.ScannedAt.Format("2006-01-02T15:04:05Z07:00"),
		ExternalScanners: secretExternals,
	}
	return writeJSON(run.SecretScanPath(runPath), out)
}

// dependencyReportFile is the on-disk shape of dependency-report.json.
// It lists every discovered vulnerability scanner (so operators can see
// which tools were probed) and the findings produced by the ones that
// successfully ran.
type dependencyReportFile struct {
	RunID           string                     `json:"run_id"`
	DiscoveredTools []scanners.ExternalScanner `json:"discovered_tools"`
	Results         []scanners.ScanResult      `json:"results"`
	GeneratedAt     string                     `json:"generated_at"`
}

func writeDependencyReport(runPath string, discovered []scanners.ExternalScanner, results []scanners.ScanResult) error {
	var depDiscovered []scanners.ExternalScanner
	for _, e := range discovered {
		if e.Kind == scanners.ScannerKindVulnerabilities || e.Kind == scanners.ScannerKindSAST {
			depDiscovered = append(depDiscovered, e)
		}
	}
	var depResults []scanners.ScanResult
	for _, r := range results {
		if r.Scanner == "gitleaks" {
			continue
		}
		depResults = append(depResults, r)
	}
	runID := ""
	if len(results) > 0 {
		runID = results[0].RunID
	}
	generatedAt := scanResultsTimestamp(results)
	out := dependencyReportFile{
		RunID:           runID,
		DiscoveredTools: depDiscovered,
		Results:         depResults,
		GeneratedAt:     generatedAt,
	}
	return writeJSON(run.DependencyReportPath(runPath), out)
}

// scanResultsTimestamp picks a stable generated-at timestamp for the
// dependency report. We use the most recent ScannedAt across the
// supplied results; an empty results slice falls back to an empty
// string so the file is still valid JSON.
func scanResultsTimestamp(results []scanners.ScanResult) string {
	if len(results) == 0 {
		return ""
	}
	latest := results[0].ScannedAt
	for _, r := range results[1:] {
		if r.ScannedAt.After(latest) {
			latest = r.ScannedAt
		}
	}
	return latest.Format("2006-01-02T15:04:05Z07:00")
}

// writeJSON marshals v as pretty-printed JSON and writes it to path
// using an atomic temp-file + rename so a concurrent reader never
// observes a half-written file.
func writeJSON(path string, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// renderScanSummary prints the deterministic, human-readable summary
// of a scan run. The shape mirrors `ai-env status` / `ai-env report`
// (label-aligned colon-separated lines) so an operator who knows one
// knows the other.
func renderScanSummary(stdout, stderr io.Writer, s scanSummary) {
	fmt.Fprintf(stdout, "env:       %s\n", s.EnvName)
	fmt.Fprintf(stdout, "run id:    %s\n", s.RunID)
	fmt.Fprintf(stdout, "run dir:   %s\n", s.RunPath)

	blocking := 0
	for _, f := range s.BuiltIn.Findings {
		if f.BlocksExport {
			blocking++
		}
	}
	for _, res := range s.ExternalResults {
		for _, f := range res.Findings {
			if f.BlocksExport {
				blocking++
			}
		}
	}

	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "built-in scanner:")
	fmt.Fprintf(stdout, "  findings:          %d\n", len(s.BuiltIn.Findings))
	fmt.Fprintf(stdout, "  entropy warnings:  %d\n", len(s.BuiltIn.EntropyWarnings))
	for _, f := range s.BuiltIn.Findings {
		fmt.Fprintf(stdout, "  - [%s] %s %s:%d (%s)\n", f.Type, f.Pattern, f.File, f.Line, f.Confidence)
	}

	available, unavailable := splitAvailability(s.External)
	fmt.Fprintln(stdout, "")
	fmt.Fprintf(stdout, "external scanners: %d available, %d missing\n", len(available), len(unavailable))
	for _, r := range s.ExternalResults {
		fmt.Fprintf(stdout, "  %s: %d findings\n", r.Scanner, len(r.Findings))
		for _, f := range r.Findings {
			fmt.Fprintf(stdout, "    - [%s] %s %s:%d (%s)\n", f.Type, f.Pattern, f.File, f.Line, f.Confidence)
		}
	}

	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "artifacts:")
	fmt.Fprintf(stdout, "  secret scan        %s\n", run.SecretScanPath(s.RunPath))
	fmt.Fprintf(stdout, "  dependency report  %s\n", run.DependencyReportPath(s.RunPath))

	fmt.Fprintln(stdout, "")
	if blocking > 0 {
		fmt.Fprintf(stdout, "result:    %d blocking finding(s); export will be blocked\n", blocking)
	} else {
		fmt.Fprintln(stdout, "result:    no blocking findings")
	}

	if len(unavailable) > 0 {
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "warning: optional scanners unavailable (install to enable):")
		for _, e := range unavailable {
			fmt.Fprintf(stderr, "  - %s (%s): %s\n", e.Name, e.Kind, e.Message)
		}
	}
	if len(s.ExternalErrors) > 0 {
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "warning: external scanner errors:")
		for _, e := range s.ExternalErrors {
			fmt.Fprintf(stderr, "  - %s: %v\n", e.Name, e.Err)
		}
	}
}

// splitAvailability partitions the discovered scanner list into
// available + unavailable buckets, preserving registry order so the
// summary output is deterministic across runs.
func splitAvailability(all []scanners.ExternalScanner) (available, unavailable []scanners.ExternalScanner) {
	for _, e := range all {
		if e.Available {
			available = append(available, e)
		} else {
			unavailable = append(unavailable, e)
		}
	}
	sort.SliceStable(available, func(i, j int) bool { return available[i].Name < available[j].Name })
	sort.SliceStable(unavailable, func(i, j int) bool { return unavailable[i].Name < unavailable[j].Name })
	return available, unavailable
}
