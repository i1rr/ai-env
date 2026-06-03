package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/i1rr/ai-env/internal/config"
	"github.com/i1rr/ai-env/internal/export"
	"github.com/i1rr/ai-env/internal/run"
	"github.com/i1rr/ai-env/internal/scanners"
	"github.com/i1rr/ai-env/internal/workspace"
)

// exportInputs bundles everything an export surface needs to construct
// an export.Input. Both `ai-env patch` and `ai-env pr` build the same
// inputs from the same on-disk artifacts; centralizing the load here
// keeps the two call sites identical except for the export.Mode they
// stamp into the resulting Input.
type exportInputs struct {
	Diff            workspace.DiffResult
	Policy          *config.PolicyConfig
	BuiltInResult   scanners.ScanResult
	ExternalResults []scanners.ScanResult
	Record          *run.Record
	RunID           string
	RunPath         string
}

// loadExportInputs assembles an exportInputs bundle for envName.
//
// It performs only the I/O steps that are common to every export
// surface: load policy, compute the workspace diff, locate the run
// directory (latest unless runID is set), read the run record, and
// load secret-scan.json + dependency-report.json into scanner result
// values. A missing run directory or scan artifact is not an error;
// the gate is designed to evaluate the absence sensibly (no findings
// equals no secret blocks).
func loadExportInputs(aiEnvDir, envName, runID string) (exportInputs, error) {
	var inputs exportInputs

	matcher, err := loadProtectedMatcher(aiEnvDir)
	if err != nil {
		return inputs, err
	}

	diff, err := workspace.Diff(aiEnvDir, envName, matcher)
	if err != nil {
		return inputs, err
	}
	inputs.Diff = diff

	policy, err := loadPolicyIfPresent(aiEnvDir)
	if err != nil {
		return inputs, err
	}
	inputs.Policy = policy

	var summary run.RunSummary
	if runID != "" {
		summary, err = run.FindRunByID(aiEnvDir, runID)
	} else {
		summary, err = run.LatestRunForEnv(aiEnvDir, envName)
	}
	if err != nil {
		if errors.Is(err, run.ErrNoRuns) {
			return inputs, nil
		}
		return inputs, err
	}
	inputs.RunID = summary.ID
	inputs.RunPath = summary.Path

	if rec, err := run.ReadRecord(summary.Path); err == nil {
		recCopy := rec
		inputs.Record = &recCopy
	} else if !errors.Is(err, run.ErrRecordNotWritten) && !os.IsNotExist(err) {
		return inputs, fmt.Errorf("read run record: %w", err)
	}

	builtIn, externals, err := loadScanArtifacts(summary.Path)
	if err != nil {
		return inputs, err
	}
	inputs.BuiltInResult = builtIn
	inputs.ExternalResults = externals

	return inputs, nil
}

// loadPolicyIfPresent reads .ai-env/policy.yaml when it exists and
// returns nil otherwise. A malformed policy file is a hard error so the
// operator does not silently get the documented defaults when their
// configured rules failed to parse; mirrors loadScannerConfig.
func loadPolicyIfPresent(aiEnvDir string) (*config.PolicyConfig, error) {
	policyPath := filepath.Join(aiEnvDir, "policy.yaml")
	if _, err := os.Stat(policyPath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat policy %s: %w", policyPath, err)
	}
	return config.LoadPolicy(policyPath)
}

// loadScanArtifacts reads secret-scan.json (for the built-in result and
// any gitleaks external result) and dependency-report.json (for
// vulnerability scanner results) from a run directory. A missing file
// is treated as "no scan was run for this artifact"; the gate handles
// the zero values gracefully.
func loadScanArtifacts(runPath string) (scanners.ScanResult, []scanners.ScanResult, error) {
	var builtIn scanners.ScanResult
	var externals []scanners.ScanResult

	secretPath := run.SecretScanPath(runPath)
	if raw, err := os.ReadFile(secretPath); err == nil {
		var file secretScanArtifact
		if err := json.Unmarshal(raw, &file); err != nil {
			return builtIn, externals, fmt.Errorf("parse %s: %w", secretPath, err)
		}
		builtIn = scanners.ScanResult{
			RunID:           file.RunID,
			Scanner:         file.Scanner,
			Findings:        file.Findings,
			EntropyWarnings: file.EntropyWarnings,
		}
		externals = append(externals, file.ExternalScanners...)
	} else if !os.IsNotExist(err) {
		return builtIn, externals, fmt.Errorf("read %s: %w", secretPath, err)
	}

	depPath := run.DependencyReportPath(runPath)
	if raw, err := os.ReadFile(depPath); err == nil {
		var file dependencyReportArtifact
		if err := json.Unmarshal(raw, &file); err != nil {
			return builtIn, externals, fmt.Errorf("parse %s: %w", depPath, err)
		}
		externals = append(externals, file.Results...)
	} else if !os.IsNotExist(err) {
		return builtIn, externals, fmt.Errorf("read %s: %w", depPath, err)
	}

	return builtIn, externals, nil
}

// secretScanArtifact mirrors the on-disk shape secretScanFile writes,
// minus the formatted timestamp field the gate does not consult. We
// keep it private to this file so the loader does not have to share an
// unexported struct with the writer in scan.go.
type secretScanArtifact struct {
	RunID            string                    `json:"run_id"`
	Scanner          string                    `json:"scanner"`
	Findings         []scanners.Finding        `json:"findings"`
	EntropyWarnings  []scanners.EntropyWarning `json:"entropy_warnings"`
	ExternalScanners []scanners.ScanResult     `json:"external_scanners,omitempty"`
}

// dependencyReportArtifact mirrors dependencyReportFile minus the
// formatted timestamp field. Symmetric helper to secretScanArtifact.
type dependencyReportArtifact struct {
	RunID   string                `json:"run_id"`
	Results []scanners.ScanResult `json:"results"`
}

// renderGateResult prints a gate verdict to stdout (warnings) and
// stderr (block reasons) in a stable, label-aligned shape that
// mirrors `ai-env scan` and `ai-env status`. Callers print this
// regardless of decision so the operator always sees what the gate
// observed.
func renderGateResult(stdout, stderr io.Writer, label string, result export.GateResult) {
	warnings := result.Warnings()
	blocks := result.BlockingReasons()

	if len(warnings) > 0 {
		fmt.Fprintln(stdout, "")
		fmt.Fprintf(stdout, "%s warnings:\n", label)
		for _, w := range warnings {
			fmt.Fprintf(stdout, "  - [%s] %s\n", w.Code, w.Message)
		}
	}
	if len(blocks) > 0 {
		fmt.Fprintln(stderr, "")
		fmt.Fprintf(stderr, "%s blocked:\n", label)
		for _, b := range blocks {
			tag := "configurable"
			if b.Hard {
				tag = "hard"
			}
			fmt.Fprintf(stderr, "  - [%s][%s] %s\n", tag, b.Code, b.Message)
		}
	}
}
