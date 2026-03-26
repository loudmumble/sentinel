package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func resetCmdFlags() {
	rootCmd.Flags().Set("help", "false")
	for _, cmd := range rootCmd.Commands() {
		cmd.Flags().Set("help", "false")
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			f.Value.Set(f.DefValue)
		})
	}
	// Reset analyze command flags explicitly to prevent state leaks
	if analyzeC, _, err := rootCmd.Find([]string{"analyze"}); err == nil {
		analyzeC.Flags().Set("type", "process")
		analyzeC.Flags().Set("pid", "0")
		analyzeC.Flags().Set("comm", "")
		analyzeC.Flags().Set("path", "")
		analyzeC.Flags().Set("operation", "")
		analyzeC.Flags().Set("uid", "0")
		analyzeC.Flags().Set("dport", "0")
	}
	// Reset monitor/trace/watch flags
	for _, name := range []string{"monitor", "trace", "watch"} {
		if c, _, err := rootCmd.Find([]string{name}); err == nil {
			c.Flags().Set("output", "json")
			c.Flags().Set("interval", "1")
		}
	}
	if c, _, err := rootCmd.Find([]string{"serve"}); err == nil {
		c.Flags().Set("output", "json")
	}
}

func executeCmd(args ...string) (string, string, error) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	resetCmdFlags()

	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	return stdout.String(), stderr.String(), err
}

func TestVersion(t *testing.T) {
	stdout, _, err := executeCmd("version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "sentinel v") {
		t.Errorf("expected version output, got: %s", stdout)
	}
}

func TestHelp(t *testing.T) {
	stdout, _, err := executeCmd("--help")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "sentinel") {
		t.Errorf("expected help output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Available Commands") {
		t.Errorf("expected 'Available Commands' in help, got: %s", stdout)
	}
}

func TestMonitorHelp(t *testing.T) {
	stdout, _, err := executeCmd("monitor", "--help")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "monitor") {
		t.Errorf("expected monitor in help, got: %s", stdout)
	}
	if !strings.Contains(stdout, "--output") {
		t.Errorf("expected --output flag, got: %s", stdout)
	}
	if !strings.Contains(stdout, "--interval") {
		t.Errorf("expected --interval flag, got: %s", stdout)
	}
}

func TestTraceHelp(t *testing.T) {
	stdout, _, err := executeCmd("trace", "--help")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "trace") {
		t.Errorf("expected trace in help, got: %s", stdout)
	}
	if !strings.Contains(stdout, "--output") {
		t.Errorf("expected --output flag, got: %s", stdout)
	}
}

func TestWatchHelp(t *testing.T) {
	stdout, _, err := executeCmd("watch", "--help")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "watch") {
		t.Errorf("expected watch in help, got: %s", stdout)
	}
	if !strings.Contains(stdout, "--paths") {
		t.Errorf("expected --paths flag, got: %s", stdout)
	}
}

func TestAnalyzeHelp(t *testing.T) {
	stdout, _, err := executeCmd("analyze", "--help")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "analyze") {
		t.Errorf("expected analyze in help, got: %s", stdout)
	}
	if !strings.Contains(stdout, "--type") {
		t.Errorf("expected --type flag, got: %s", stdout)
	}
}

func TestServeHelp(t *testing.T) {
	stdout, _, err := executeCmd("serve", "--help")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "serve") {
		t.Errorf("expected serve in help, got: %s", stdout)
	}
}

func TestStatusHelp(t *testing.T) {
	stdout, _, err := executeCmd("status", "--help")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "status") {
		t.Errorf("expected status in help, got: %s", stdout)
	}
}

func TestSubcommandExists(t *testing.T) {
	expected := map[string]bool{
		"monitor": false,
		"trace":   false,
		"watch":   false,
		"analyze": false,
		"serve":   false,
		"status":  false,
		"version": false,
	}
	for _, cmd := range rootCmd.Commands() {
		if _, ok := expected[cmd.Name()]; ok {
			expected[cmd.Name()] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}

func TestRootCmdUse(t *testing.T) {
	if rootCmd.Use != "sentinel" {
		t.Errorf("expected root cmd use 'sentinel', got %q", rootCmd.Use)
	}
}

func TestRootCmdShort(t *testing.T) {
	if rootCmd.Short == "" {
		t.Error("root cmd short description is empty")
	}
}

func TestRootCmdLong(t *testing.T) {
	if rootCmd.Long == "" {
		t.Error("root cmd long description is empty")
	}
}

func TestGetRootCmd(t *testing.T) {
	cmd := GetRootCmd()
	if cmd == nil {
		t.Fatal("GetRootCmd returned nil")
	}
	if cmd != rootCmd {
		t.Error("GetRootCmd should return rootCmd")
	}
}

func TestVersionString(t *testing.T) {
	if version == "" {
		t.Error("version string is empty")
	}
}

func TestAnalyzeProcessEvent(t *testing.T) {
	stdout, _, err := executeCmd("analyze", "--type", "process", "--pid", "1", "--comm", "bash", "--uid", "0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "root_shell") {
		t.Errorf("expected root_shell anomaly for uid=0 bash, got: %s", stdout)
	}
}

func TestAnalyzeFileEvent(t *testing.T) {
	stdout, _, err := executeCmd("analyze", "--type", "file", "--path", "/etc/passwd", "--operation", "modify")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "critical_file_mod") {
		t.Errorf("expected critical_file_mod anomaly, got: %s", stdout)
	}
}

func TestAnalyzeNetworkEvent(t *testing.T) {
	stdout, _, err := executeCmd("analyze", "--type", "network", "--dport", "7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "unusual_port") {
		t.Errorf("expected unusual_port anomaly, got: %s", stdout)
	}
}

func TestAnalyzeSyscallEvent(t *testing.T) {
	stdout, _, err := executeCmd("analyze", "--type", "syscall", "--pid", "1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout == "" {
		t.Error("expected non-empty output for syscall analyze")
	}
}

func TestAnalyzeUnknownType(t *testing.T) {
	_, _, err := executeCmd("analyze", "--type", "bogus")
	if err == nil {
		t.Error("expected error for unknown event type")
	}
}

func TestHelpContainsEBPF(t *testing.T) {
	stdout, _, _ := executeCmd("--help")
	if !strings.Contains(strings.ToLower(stdout), "ebpf") {
		t.Errorf("expected eBPF mention in help, got: %s", stdout)
	}
}

func TestHelpContainsProbes(t *testing.T) {
	stdout, _, _ := executeCmd("--help")
	lower := strings.ToLower(stdout)
	if !strings.Contains(lower, "monitor") {
		t.Errorf("expected monitor in help, got: %s", stdout)
	}
}
