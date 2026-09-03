package doctor

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestCheckConfigRoundTrip verifies that the config round-trip check succeeds
// with a valid config containing custom rules (rules: as a list) and framework
// extensions. This is the regression guard for the B11.5.4 unified-config schema
// conflict where rulesconfig and customrules disagreed on the rules: schema.
func TestCheckConfigRoundTrip(t *testing.T) {
	ok, errMsg := checkConfigRoundTrip()
	if !ok {
		t.Fatalf("config round-trip check failed: %s", errMsg)
	}
}

func TestEveryNonPassCheckHasRemediation(t *testing.T) {
	report, err := Run()
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(report.Checks) == 0 {
		t.Fatal("Run() returned no structured checks")
	}
	for _, check := range report.Checks {
		if check.Status != "pass" && check.Remediation == "" {
			t.Errorf("check %q has status %q without remediation", check.Name, check.Status)
		}
	}
}

func TestRunTreatsMissingRemoteAsLocalReady(t *testing.T) {
	repository := t.TempDir()
	command := exec.Command("git", "init", "-q")
	command.Dir = repository
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v: %s", err, output)
	}

	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("get current directory: %v", err)
	}
	if err := os.Chdir(repository); err != nil {
		t.Fatalf("change to temporary repository: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore current directory: %v", err)
		}
	})
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	report, err := Run()
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if report.RemoteURL != "" {
		t.Fatalf("expected empty remote URL, got %q", report.RemoteURL)
	}

	for _, check := range report.Checks {
		if check.Name != "remote" {
			continue
		}
		if check.Status != "pass" {
			t.Fatalf("optional remote should not reduce local readiness: %+v", check)
		}
		if !strings.Contains(check.Message, "local scans work without one") {
			t.Fatalf("remote check must explain the local-first behavior: %+v", check)
		}
		return
	}
	t.Fatal("doctor report did not include the remote check")
}
