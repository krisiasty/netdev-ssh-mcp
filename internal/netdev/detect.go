package netdev

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

// Platform detection runs when a caller omits device_type. It takes one SSH
// connection: the server's identification string picks a single probe
// command that the likely platform accepts, and anchored markers in that
// command's output decide the platform. The identification string alone never
// decides, because several platforms send the same one (EOS and JunOS both
// send plain OpenSSH). Results are cached per host:port for detectCacheTTL.
//
// Everything the device sends is untrusted: markers are anchored to the start
// of a line so a hostname or description cannot satisfy them, and values
// echoed back to the caller are sanitized and truncated.

var runProbe = sshclient.Probe

// detectCacheTTL bounds how long a detected platform is reused. A device
// replaced at the same address is re-detected after this, or sooner if a
// command fails with a syntax error.
const detectCacheTTL = time.Hour

// now is replaced in tests.
var now = time.Now

// errUnsupportedPlatform marks a device that was identified but is not
// supported; passing device_type would not help.
var errUnsupportedPlatform = errors.New("unsupported platform")

type detectSource string

const (
	sourceExplicit detectSource = "explicit"
	sourceProbe    detectSource = "probe"
	sourceCache    detectSource = "cache"
)

// resolvedType is the device type a tool call will use and where it came from.
type resolvedType struct {
	dt     deviceType
	source detectSource
	// The fields below are set only for detected types and are sanitized.
	serverVersion string
	version       string
}

// identClass groups SSH identification strings by what they reveal.
type identClass int

const (
	identUnknown       identClass = iota
	identPlainOpenSSH             // Arista EOS, Juniper JunOS
	identPKIX                     // Cisco NX-OS (PKIX-SSH)
	identCisco                    // Cisco IOS / IOS-XE
	identObfuscated               // FortiOS: a random token, or FortiSSH_x.y on older releases
	identLinux                    // Debian or Ubuntu based, e.g. Cumulus Linux
	identCiscoBusiness            // Cisco Business switch OS, e.g. Catalyst 1200
)

var (
	plainOpenSSHRe = regexp.MustCompile(`^OpenSSH_\d+(?:\.\d+)*(?:p\d+)?$`)
	obfuscatedRe   = regexp.MustCompile(`^[A-Za-z0-9]{6,16}$`)
	linuxDistroRe  = regexp.MustCompile(`(?i)\b(?:debian|ubuntu)\b`)
)

// classifyIdent classifies an SSH identification string such as
// "SSH-2.0-OpenSSH_9.6 PKIX[12.5.1]".
func classifyIdent(serverVersion string) identClass {
	ident := serverVersion
	for _, prefix := range []string{"SSH-2.0-", "SSH-1.99-"} {
		ident = strings.TrimPrefix(ident, prefix)
	}
	software, _, _ := strings.Cut(ident, " ")

	switch {
	case linuxDistroRe.MatchString(ident):
		return identLinux
	case strings.HasPrefix(software, "OpenSSH_") && strings.HasSuffix(software, ".RL"):
		return identCiscoBusiness
	case strings.Contains(ident, "PKIX["):
		return identPKIX
	case strings.HasPrefix(software, "Cisco-"):
		return identCisco
	case plainOpenSSHRe.MatchString(ident):
		return identPlainOpenSSH
	case obfuscatedRe.MatchString(ident), strings.HasPrefix(software, "FortiSSH_"):
		return identObfuscated
	default:
		return identUnknown
	}
}

const (
	probeShowVersion  = "show version"
	probeSystemStatus = "get system status"
)

// probeCommandFor returns the one command to run for an identification
// class, chosen so the likely platform accepts it. Platforms that are known
// to be unsupported get an error before anything runs: on the Cisco Business
// switch OS an exec request hangs, and on Linux it reaches a shell.
func probeCommandFor(c identClass, serverVersion string) (string, error) {
	switch c {
	case identLinux:
		return "", fmt.Errorf("%w: the SSH server %q is a Linux distribution; Linux-based network operating systems such as Cumulus Linux are not supported yet",
			errUnsupportedPlatform, displayValue(serverVersion))
	case identCiscoBusiness:
		return "", fmt.Errorf("%w: the SSH server %q is the Cisco Business switch OS (Catalyst 1200/1300, CBS), which does not answer SSH exec requests",
			errUnsupportedPlatform, displayValue(serverVersion))
	case identObfuscated:
		return probeSystemStatus, nil
	default:
		return probeShowVersion, nil
	}
}

// platformMarker identifies a platform from probe output. Every pattern is
// anchored to the start of a line.
type platformMarker struct {
	dt deviceType
	re *regexp.Regexp
}

func marker(dt deviceType, expr string) platformMarker {
	return platformMarker{dt: dt, re: regexp.MustCompile(`(?m)` + expr)}
}

var probeMarkers = map[string][]platformMarker{
	probeShowVersion: {
		// The model line, such as "Arista DCS-7050CX3-32C-R". It must be the
		// whole line: IOS starts a line with the hostname ("<hostname>
		// uptime is ..."), so a device named "Arista" must not match.
		marker(deviceTypeEOS, `^Arista [\w.-]+\s*$`),
		marker(deviceTypeEOS, `^Software image version:\s+\d`),
		marker(deviceTypeJunos, `^Junos:\s+\d`),
		marker(deviceTypeJunos, `^JUNOS Software Release \[`),
		marker(deviceTypeNXOS, `^\s*Cisco Nexus Operating System \(NX-OS\) Software`),
		marker(deviceTypeIOS, `^\s*Cisco IOS(?: XE)? Software`),
		marker(deviceTypeIOS, `^\s*IOS \(tm\) `),
	},
	probeSystemStatus: {
		marker(deviceTypeFortiOS, `^Version:\s+Forti\S+\s+v\d`),
	},
}

// versionPatterns extract a short version string for detect_platform. The
// capture is limited to characters that appear in version numbers.
var versionPatterns = map[deviceType]*regexp.Regexp{
	deviceTypeEOS:     regexp.MustCompile(`(?m)^Software image version:\s+([\w.()-]+)`),
	deviceTypeJunos:   regexp.MustCompile(`(?m)^(?:Junos:\s+|JUNOS Software Release \[)([\w.()-]+)`),
	deviceTypeNXOS:    regexp.MustCompile(`(?m)^\s*(?:NXOS|system):\s+version\s+([\w.()-]+)`),
	deviceTypeIOS:     regexp.MustCompile(`(?m)^\s*(?:Cisco IOS(?: XE)? Software|IOS \(tm\)).*?Version\s+([\w.()-]+)`),
	deviceTypeFortiOS: regexp.MustCompile(`(?m)^Version:\s+Forti\S+\s+(v[\w.()-]+)`),
}

// matchProbeOutput decides the platform from a probe command's output. It
// requires exactly one platform to match.
func matchProbeOutput(command, output string) (deviceType, error) {
	var found []deviceType
	for _, m := range probeMarkers[command] {
		if m.re.MatchString(output) && !slices.Contains(found, m.dt) {
			found = append(found, m.dt)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", fmt.Errorf("the output of %q matched no supported platform", command)
	default:
		return "", fmt.Errorf("the output of %q matched several platforms (%v)", command, found)
	}
}

func extractVersion(dt deviceType, output string) string {
	re, ok := versionPatterns[dt]
	if !ok {
		return ""
	}
	if m := re.FindStringSubmatch(output); m != nil {
		return displayValue(m[1])
	}
	return ""
}

// displayValue makes a device-supplied value safe to echo back: control
// characters are removed and the length is capped.
func displayValue(s string) string {
	const maxLen = 80
	s = strings.TrimSpace(sanitizeLog(s))
	if len(s) > maxLen {
		s = s[:maxLen] + "..."
	}
	return s
}

type cacheEntry struct {
	r       resolvedType
	expires time.Time
}

var detectCache = struct {
	sync.Mutex
	m map[string]cacheEntry
}{m: map[string]cacheEntry{}}

func cacheKey(host string, port int) string {
	if port == 0 {
		port = 22
	}
	return strings.ToLower(strings.TrimSpace(host)) + ":" + strconv.Itoa(port)
}

func cachedType(key string) (resolvedType, bool) {
	detectCache.Lock()
	defer detectCache.Unlock()
	e, ok := detectCache.m[key]
	if !ok {
		return resolvedType{}, false
	}
	if now().After(e.expires) {
		delete(detectCache.m, key)
		return resolvedType{}, false
	}
	r := e.r
	r.source = sourceCache
	return r, true
}

func storeType(key string, r resolvedType) {
	detectCache.Lock()
	defer detectCache.Unlock()
	detectCache.m[key] = cacheEntry{r: r, expires: now().Add(detectCacheTTL)}
}

func forgetType(key string) {
	detectCache.Lock()
	defer detectCache.Unlock()
	delete(detectCache.m, key)
}

// resolveDeviceType returns the device type for a tool call: the caller's
// device_type if given, otherwise a cached detection, otherwise a fresh probe.
// refresh skips the cache.
func resolveDeviceType(ctx context.Context, cfg sshclient.ConnConfig, raw string, refresh bool) (resolvedType, error) {
	dt, err := normalizeDeviceType(raw)
	if err != nil {
		return resolvedType{}, err
	}
	if dt != "" {
		return resolvedType{dt: dt, source: sourceExplicit}, nil
	}

	key := cacheKey(cfg.Host, cfg.Port)
	if !refresh {
		if r, ok := cachedType(key); ok {
			return r, nil
		}
	}

	res, err := runProbe(ctx, cfg, func(serverVersion string) (string, error) {
		return probeCommandFor(classifyIdent(serverVersion), serverVersion)
	})
	if err != nil {
		// Connection, authentication and host key errors would fail the
		// command as well, so suggesting device_type would not help.
		return resolvedType{}, fmt.Errorf("detect platform: %w", err)
	}

	dt, err = matchProbeOutput(res.Command, res.Output)
	if err != nil {
		return resolvedType{}, fmt.Errorf("could not detect the platform of %s (SSH server %q): %w; pass device_type (%s)",
			cfg.Host, displayValue(res.ServerVersion), err, supportedDeviceTypes)
	}

	r := resolvedType{
		dt:            dt,
		source:        sourceProbe,
		serverVersion: displayValue(res.ServerVersion),
		version:       extractVersion(dt, res.Output),
	}
	storeType(key, r)
	slog.Info("platform detected", "host", sanitizeLog(cfg.Host), "device_type", string(dt), "ssh_server", r.serverVersion) //nolint:gosec // G706: values are sanitized before logging
	return r, nil
}

const supportedDeviceTypes = "eos, ios, nxos, junos or fortios"

// syntaxErrorRe matches the messages platforms print for a command they do
// not understand, which is what running another platform's syntax produces.
var syntaxErrorRe = regexp.MustCompile(`(?mi)^\s*(?:% ?Invalid (?:input|command)|% ?Incomplete command|% ?Ambiguous command|syntax error|unknown command|Unknown action|Command fail\.|command parse error)`)

func looksLikeSyntaxError(text string) bool {
	return syntaxErrorRe.MatchString(text)
}

// syntaxCheckLines is how much of a successful command's output is checked
// for a rejection message. Devices print one at the start, while text later
// in the output (banners, descriptions, logs) is chosen by whoever configured
// the device and must not be read as a rejection.
const syntaxCheckLines = 10

// rejectedSyntax reports whether the device rejected the command syntax:
// from the start of a successful command's output, or from the output kept
// in a failed command's error. That output is only classified here; it is
// never shown to the caller, because it is untrusted and can hold secrets.
func rejectedSyntax(output string, runErr error) bool {
	if looksLikeSyntaxError(firstLines(output, syntaxCheckLines)) {
		return true
	}
	var cmdErr *sshclient.CommandError
	return errors.As(runErr, &cmdErr) && looksLikeSyntaxError(string(cmdErr.Output))
}

// firstLines returns the first n lines of s.
func firstLines(s string, n int) string {
	i := 0
	for ; n > 0; n-- {
		next := strings.IndexByte(s[i:], '\n')
		if next < 0 {
			return s
		}
		i += next + 1
	}
	return s[:i]
}

// requestCancelled reports whether err comes from the MCP client cancelling
// the request, or its deadline passing, rather than from the device.
func requestCancelled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// logFailure logs a failed tool call. A cancelled request is a normal client
// action, not a device failure, so it is logged at Info rather than Error.
func logFailure(tool string, err error, attrs ...any) {
	if requestCancelled(err) {
		slog.Info(tool+" cancelled by the client", attrs...)
		return
	}
	slog.Error(tool+" failed", append(attrs, "err", err)...)
}

// detectedNotice tells the caller which device type a detected call used, so
// it can pass it on later calls.
func detectedNotice(r resolvedType) string {
	switch r.source {
	case sourceProbe:
		return fmt.Sprintf("device_type: %s (auto-detected over SSH). Pass device_type=%s on later calls to this host to skip detection.", r.dt, r.dt)
	case sourceCache:
		return fmt.Sprintf("device_type: %s (auto-detected earlier and cached by this server). Pass device_type=%s on later calls to this host to skip detection.", r.dt, r.dt)
	default:
		return ""
	}
}

// explicitTypeHint suggests detection when a command the caller typed for an
// explicit device_type was rejected as invalid syntax.
func explicitTypeHint(r resolvedType) string {
	return fmt.Sprintf("The device rejected the command syntax. If device_type=%s is not this device's platform, omit device_type to auto-detect it, or call detect_platform.", r.dt)
}

// detectedRejectedNotice explains a rejected command after detection: the
// detected type may be wrong, so it was forgotten.
const detectedRejectedNotice = "The device rejected the command syntax. The detected device_type was forgotten, so the next call without device_type detects the platform again."

// afterRun inspects a command's outcome. A syntax error on a detected type
// drops the cached detection so the next call probes again; on an explicit
// type it yields a hint. It returns the notices to append to the result.
func afterRun(cfg sshclient.ConnConfig, r resolvedType, output string, runErr error) []mcp.Content {
	syntaxErr := rejectedSyntax(output, runErr)

	var notices []mcp.Content
	switch r.source {
	case sourceProbe, sourceCache:
		notices = append(notices, &mcp.TextContent{Text: detectedNotice(r)})
		if syntaxErr {
			forgetType(cacheKey(cfg.Host, cfg.Port))
			notices = append(notices, &mcp.TextContent{Text: detectedRejectedNotice})
		}
	case sourceExplicit:
		if syntaxErr {
			notices = append(notices, &mcp.TextContent{Text: explicitTypeHint(r)})
		}
	}
	return notices
}

// runError wraps a failed command, adding the same notice afterRun would
// have appended to a successful result.
func runError(tool string, cfg sshclient.ConnConfig, r resolvedType, err error) error {
	if requestCancelled(err) {
		// The caller has gone; a detection notice or hint means nothing.
		return fmt.Errorf("%s: %w", tool, err)
	}
	var extra []string
	for _, c := range afterRun(cfg, r, "", err) {
		if t, ok := c.(*mcp.TextContent); ok {
			extra = append(extra, t.Text)
		}
	}
	if len(extra) == 0 {
		return fmt.Errorf("%s: %w", tool, err)
	}
	return fmt.Errorf("%s: %w. %s", tool, err, strings.Join(extra, " "))
}
