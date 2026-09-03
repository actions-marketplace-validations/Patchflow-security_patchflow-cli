package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type codedError struct{}

func (codedError) Error() string { return "coded" }
func (codedError) ExitCode() int { return 7 }

func TestHumanFormatterPrint(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, false, false)

	type sample struct {
		Name  string
		Count int
	}
	if err := f.Print(sample{Name: "test", Count: 42}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "{Name:test Count:42}\n"
	if got := buf.String(); got != want {
		t.Errorf("Print() = %q, want %q", got, want)
	}
}

func TestHumanFormatterPrintString(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, false, false)
	if err := f.Print("hello world"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "hello world\n"
	if got := buf.String(); got != want {
		t.Errorf("Print() = %q, want %q", got, want)
	}
}

func TestJSONFormatterPrint(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, true, false)

	type sample struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	if err := f.Print(sample{Name: "test", Count: 42}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `{
  "name": "test",
  "count": 42
}` + "\n"
	if got := buf.String(); got != want {
		t.Errorf("Print() = %q, want %q", got, want)
	}
}

func TestHumanFormatterPrintSuccess(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, false, false)
	if err := f.PrintSuccess("done"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, "✓") {
		t.Errorf("PrintSuccess() = %q, want check mark", got)
	}
	if got := buf.String(); !strings.Contains(got, "done") {
		t.Errorf("PrintSuccess() = %q, want message", got)
	}
}

func TestHumanFormatterPrintSuccessNoColor(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, false, true)
	if err := f.PrintSuccess("done"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "[OK] done\n"
	if got := buf.String(); got != want {
		t.Errorf("PrintSuccess() = %q, want %q", got, want)
	}
}

func TestHumanFormatterPrintError(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, false, false)
	inputErr := errors.New("boom")
	if err := f.PrintError(inputErr); !errors.Is(err, inputErr) || !IsErrorReported(err) {
		t.Fatalf("PrintError() = %v, want a reported wrapper around the input error", err)
	}
	if got := buf.String(); !strings.Contains(got, "✗") {
		t.Errorf("PrintError() = %q, want cross mark", got)
	}
	if got := buf.String(); !strings.Contains(got, "boom") {
		t.Errorf("PrintError() = %q, want error message", got)
	}
}

func TestHumanFormatterPrintErrorNoColor(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, false, true)
	inputErr := errors.New("boom")
	if err := f.PrintError(inputErr); !errors.Is(err, inputErr) || !IsErrorReported(err) {
		t.Fatalf("PrintError() = %v, want a reported wrapper around the input error", err)
	}
	want := "[ERR] error: boom\n"
	if got := buf.String(); got != want {
		t.Errorf("PrintError() = %q, want %q", got, want)
	}
}

func TestJSONFormatterPrintSuccess(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, true, false)
	if err := f.PrintSuccess("done"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `{
  "success": true,
  "message": "done"
}` + "\n"
	if got := buf.String(); got != want {
		t.Errorf("PrintSuccess() = %q, want %q", got, want)
	}
}

func TestJSONFormatterPrintError(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, true, false)
	inputErr := errors.New("boom")
	if err := f.PrintError(inputErr); !errors.Is(err, inputErr) || !IsErrorReported(err) {
		t.Fatalf("PrintError() = %v, want a reported wrapper around the input error", err)
	}
	want := `{
  "error": "boom"
}` + "\n"
	if got := buf.String(); got != want {
		t.Errorf("PrintError() = %q, want %q", got, want)
	}
}

func TestReportedErrorPreservesExitCode(t *testing.T) {
	err := MarkErrorReported(codedError{})
	code, ok := err.(interface{ ExitCode() int })
	if !ok || code.ExitCode() != 7 {
		t.Fatalf("reported error did not preserve exit code: %v", err)
	}
}

func TestHumanFormatterPrintTable(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, false, false)
	if err := f.PrintTable([]string{"Name", "Status"}, [][]string{{"foo", "ok"}, {"bar", "fail"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "Name") {
		t.Errorf("PrintTable() missing header Name: %q", got)
	}
	if !strings.Contains(got, "Status") {
		t.Errorf("PrintTable() missing header Status: %q", got)
	}
	if !strings.Contains(got, "foo") {
		t.Errorf("PrintTable() missing row foo: %q", got)
	}
}

func TestJSONFormatterPrintTable(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, true, false)
	if err := f.PrintTable([]string{"Name", "Status"}, [][]string{{"foo", "ok"}, {"bar", "fail"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `[
  {
    "Name": "foo",
    "Status": "ok"
  },
  {
    "Name": "bar",
    "Status": "fail"
  }
]` + "\n"
	if got := buf.String(); got != want {
		t.Errorf("PrintTable() = %q, want %q", got, want)
	}
}

func TestHumanFormatterPrintTableEmptyHeaders(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, false, false)
	if err := f.PrintTable([]string{}, [][]string{{"a"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := buf.String(); got != "" {
		t.Errorf("PrintTable() = %q, want empty", got)
	}
}

func TestJSONFormatterPrintTableEmptyHeaders(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewWriter(buf, true, false)
	if err := f.PrintTable([]string{}, [][]string{{"a"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := buf.String(); got != "" {
		t.Errorf("PrintTable() = %q, want empty", got)
	}
}
