package cmd

import "testing"

func TestJSONFlagRequested(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "absent", args: []string{"scan", "run"}, want: false},
		{name: "global flag", args: []string{"scan", "run", "--json"}, want: true},
		{name: "explicit true", args: []string{"--json=true", "scan", "run"}, want: true},
		{name: "explicit false", args: []string{"scan", "run", "--json=false"}, want: false},
		{name: "last value enables", args: []string{"--json=false", "scan", "run", "--json"}, want: true},
		{name: "last value disables", args: []string{"--json", "scan", "run", "--json=false"}, want: false},
		{name: "unrelated", args: []string{"scan", "run", "--format", "json"}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := jsonFlagRequested(tc.args); got != tc.want {
				t.Fatalf("jsonFlagRequested(%q) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}
