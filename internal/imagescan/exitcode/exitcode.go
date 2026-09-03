// Package exitcode defines structured exit codes for the PatchFlow Image
// Scanner CLI.
//
// Structured codes let CI/CD systems distinguish failure modes and act
// accordingly (retry on network errors, fail builds on blocking findings,
// alert on internal errors) instead of treating every non-zero exit as
// identical.
//
//	0 = scan completed, no blocking findings
//	1 = blocking findings found
//	2 = config error
//	3 = scanner internal error
//	4 = network/registry error
//	5 = auth error
//	6 = timeout exceeded
package exitcode

const (
	// Success means the scan completed with no blocking findings.
	Success = 0

	// FindingsFound means blocking findings were detected (severity >= threshold).
	FindingsFound = 1

	// ConfigError means the configuration is invalid or missing.
	ConfigError = 2

	// InternalError means the scanner encountered an internal error.
	InternalError = 3

	// NetworkError means a network/registry call failed (pull, manifest fetch).
	NetworkError = 4

	// AuthError means registry authentication failed.
	AuthError = 5

	// Timeout means the scan exceeded its time budget.
	Timeout = 6
)

// String returns a human-readable description of the exit code.
func String(code int) string {
	switch code {
	case Success:
		return "success"
	case FindingsFound:
		return "blocking findings found"
	case ConfigError:
		return "configuration error"
	case InternalError:
		return "internal scanner error"
	case NetworkError:
		return "network or registry error"
	case AuthError:
		return "authentication error"
	case Timeout:
		return "timeout exceeded"
	default:
		return "unknown error"
	}
}
