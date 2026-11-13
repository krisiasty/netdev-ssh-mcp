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
	// vdomMode is the FortiOS "Virtual domain configuration", such as
	// "multiple" or "disable". It describes the device, not the account,
	// so it can be cached per host.
	vdomMode string
	// currentVDOM is the FortiOS "Current virtual domain" this call's probe
	// read. It depends on the account, so it is never cached: it is set only
	// when source is sourceProbe.
	currentVDOM string
}

// identClass groups SSH identification strings by what they reveal.
type identClass int

const (
	identUnknown       identClass = iota
	identPlainOpenSSH             // Arista EOS, Juniper JunOS
	identPKIX                     // Cisco NX-OS (PKIX-SSH)
	identCisco                    // Cisco IOS / IOS-XE
	identObfuscated               // FortiOS: a random token, or FortiSSH_x.y on older releases
	identLinux                    // Debian or Ubuntu based; /etc/os-release tells Cumulus Linux 4.x from other distributions
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
	probeOSRelease    = "cat /etc/os-release"
)

// probeCommandFor returns the one command to run for an identification
// class, chosen so the likely platform accepts it, and the terminal to
// request for it (nil for none). Platforms that are known to be unsupported
// get an error before anything runs: on the Cisco Business switch OS an exec
// request hangs. A Linux system reaches a shell, so the probe only reads
// /etc/os-release. The FortiOS probe's output can be long enough to page
// (see terminalFor).
func probeCommandFor(c identClass, serverVersion string) (string, *sshclient.Terminal, error) {
	switch c {
	case identLinux:
		return probeOSRelease, nil, nil
	case identCiscoBusiness:
		return "", nil, fmt.Errorf("%w: the SSH server %q is the Cisco Business switch OS (Catalyst 1200/1300, CBS), which does not answer SSH exec requests",
			errUnsupportedPlatform, displayValue(serverVersion))
	case identObfuscated:
		return probeSystemStatus, terminalFor(deviceTypeFortiOS), nil
	default:
		return probeShowVersion, nil, nil
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
		// FortiOS writes its CLI prompt before the output, on the same line.
		marker(deviceTypeFortiOS, `^(?:`+fortiOSPromptPattern+`)?Version:\s+Forti\S+\s+v\d`),
	},
}

// versionPatterns extract a short version string for detect_platform. The
// capture is limited to characters that appear in version numbers.
var versionPatterns = map[deviceType]*regexp.Regexp{
	deviceTypeEOS:     regexp.MustCompile(`(?m)^Software image version:\s+([\w.()-]+)`),
	deviceTypeJunos:   regexp.MustCompile(`(?m)^(?:Junos:\s+|JUNOS Software Release \[)([\w.()-]+)`),
	deviceTypeNXOS:    regexp.MustCompile(`(?m)^\s*(?:NXOS|system):\s+version\s+([\w.()-]+)`),
	deviceTypeIOS:     regexp.MustCompile(`(?m)^\s*(?:Cisco IOS(?: XE)? Software|IOS \(tm\)).*?Version\s+([\w.()-]+)`),
	deviceTypeFortiOS: regexp.MustCompile(`(?m)^(?:` + fortiOSPromptPattern + `)?Version:\s+Forti\S+\s+(v[\w.()-]+)`),
	// The value may be quoted and the line may end in \r.
	deviceTypeCumulus4x: regexp.MustCompile(`(?m)^VERSION_ID="?([\w.+~-]+)"?\r?$`),
}

var (
	osReleaseCumulusRe   = regexp.MustCompile(`(?m)^ID="?cumulus-linux"?\r?$`)
	osReleaseVersionRe   = versionPatterns[deviceTypeCumulus4x]
	osReleaseVersion4xRe = regexp.MustCompile(`(?m)^VERSION_ID="?4\.[\w.+~-]*"?\r?$`)
)

// matchOSRelease decides whether the output of probeOSRelease is Cumulus
// Linux 4.x. Both ID and VERSION_ID must be whole lines, so a value echoed
// inside another line cannot satisfy them. Anything else is unsupported and
// passing device_type would not help.
func matchOSRelease(output string) (deviceType, error) {
	if osReleaseCumulusRe.MatchString(output) {
		if osReleaseVersion4xRe.MatchString(output) {
			return deviceTypeCumulus4x, nil
		}
		if m := osReleaseVersionRe.FindStringSubmatch(output); m != nil {
			return "", fmt.Errorf("%w: unsupported release: Cumulus Linux %s is not supported; only 4.x (cumulus4x) is",
				errUnsupportedPlatform, displayValue(m[1]))
		}
	}
	return "", fmt.Errorf("%w: the SSH server is a Linux system that is not Cumulus Linux 4.x (cumulus4x is the only supported Linux platform)",
		errUnsupportedPlatform)
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

// fortiOSStatusField returns the value re captures from FortiOS "get system
// status" output, made safe to echo back, or "" on other platforms or when
// the field is missing. vdomConfigRe gives the "Virtual domain
// configuration", currentVDOMRe the "Current virtual domain".
func fortiOSStatusField(dt deviceType, re *regexp.Regexp, output string) string {
	if dt != deviceTypeFortiOS {
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

	res, err := runProbe(ctx, cfg, func(serverVersion string) (string, *sshclient.Terminal, error) {
		return probeCommandFor(classifyIdent(serverVersion), serverVersion)
	})
	if errors.Is(err, errUnsupportedPlatform) {
		// Identified, and known not to be supported: an answer, not a failure.
		slog.Info("platform detection: unsupported platform", "host", sanitizeLog(cfg.Host)) //nolint:gosec // G706: value is sanitized before logging
		return resolvedType{}, fmt.Errorf("detect platform: %w", err)
	}
	if err != nil {
		logFailure(ctx, "platform detection", err, "host", cfg.Host)
		// Connection, authentication and host key errors would fail the
		// command as well, so suggesting device_type would not help.
		return resolvedType{}, fmt.Errorf("detect platform: %w", err)
	}

	if res.Command == probeOSRelease {
		dt, err = matchOSRelease(res.Output)
		if errors.Is(err, errUnsupportedPlatform) {
			slog.Info("platform detection: unsupported platform", "host", sanitizeLog(cfg.Host)) //nolint:gosec // G706: value is sanitized before logging
			return resolvedType{}, fmt.Errorf("detect platform: %w", err)
		}
	} else {
		dt, err = matchProbeOutput(res.Command, res.Output)
	}
	if err != nil {
		return resolvedType{}, fmt.Errorf("could not detect the platform of %s (SSH server %q): %w; pass device_type (%s)",
			cfg.Host, displayValue(res.ServerVersion), err, supportedDeviceTypes)
	}

	r := resolvedType{
		dt:            dt,
		source:        sourceProbe,
		serverVersion: displayValue(res.ServerVersion),
		version:       extractVersion(dt, res.Output),
		vdomMode:      fortiOSStatusField(dt, vdomConfigRe, res.Output),
	}
	storeType(key, r)
	// For this call only, not the cache: it depends on the account.
	r.currentVDOM = fortiOSStatusField(dt, currentVDOMRe, res.Output)
	slog.Info("platform detected", "host", sanitizeLog(cfg.Host), "device_type", string(dt), "ssh_server", r.serverVersion) //nolint:gosec // G706: values are sanitized before logging
	return r, nil
}

// resolveTarget returns the connection config and device type for a tool
// that runs a device command. Every such tool gets its config here, so none
// can skip the Linux check: unless the type is cumulus4x, the config refuses
// a Linux SSH server before a session is opened. On a Linux system bash runs
// the command, and only the cumulus4x checks are written for that; an
// explicit device_type is never checked against the device otherwise.
func resolveTarget(ctx context.Context, host string, port int, username, rawType string) (sshclient.ConnConfig, resolvedType, error) {
	cfg := connConfig(host, port, username)
	rt, err := resolveDeviceType(ctx, cfg, rawType, false)
	if err != nil {
		return cfg, rt, err
	}
	if rt.dt != deviceTypeCumulus4x {
		cfg.CheckServerVersion = refuseLinuxServer
	}
	cfg.Terminal = terminalFor(rt.dt)
	return cfg, rt, nil
}

// refuseLinuxServer is the CheckServerVersion for every device type other
// than cumulus4x.
func refuseLinuxServer(serverVersion string) error {
	if classifyIdent(serverVersion) == identLinux {
		return fmt.Errorf("%w: it identifies as %q, a Linux system; only device_type cumulus4x is supported on Linux",
			errUnsupportedPlatform, displayValue(serverVersion))
	}
	return nil
}

const supportedDeviceTypes = "eos, ios, nxos, junos, fortios or cumulus4x"

// syntaxErrorRe matches the messages platforms print for a command they do
// not understand, which is what running another platform's syntax produces.
var syntaxErrorRe = regexp.MustCompile(`(?mi)^\s*(?:ERROR: Command not found|(?:-?bash: (?:line \d+: )?)?[\w.-]+: command not found|% ?Invalid (?:input|command)|% ?Incomplete command|% ?Ambiguous command|syntax error|unknown command|Unknown action|Command fail\.|command parse error)`)

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

// requestCancelled reports whether the MCP client cancelled the request ctx
// belongs to. It looks at ctx rather than at the error: a TCP connect or DNS
// timeout towards the device also matches context.DeadlineExceeded, and must
// still be reported as a device failure.
func requestCancelled(ctx context.Context) bool {
	return ctx.Err() != nil
}

// logFailure logs a failed tool call. A cancelled request is a normal client
// action, and an unsupported platform is an answer, not a device failure, so
// both are logged at Info rather than Error.
func logFailure(ctx context.Context, tool string, err error, attrs ...any) {
	if requestCancelled(ctx) {
		slog.Info(tool+" cancelled by the client", attrs...)
		return
	}
	if answerError(err) {
		slog.Info(tool+": refused", append(attrs, "err", err)...)
		return
	}
	if errors.Is(err, errUnsupportedPlatform) {
		// The device was identified as one the device type does not
		// support (refuseLinuxServer): an answer, not a failure. The
		// error holds the reason and the server identification, already
		// passed through displayValue.
		slog.Info(tool+": unsupported platform", append(attrs, "err", err)...)
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

// explicitTypeHint explains a command the caller typed for an explicit
// device_type that the device rejected as invalid syntax. Usually the
// command is wrong for that platform, so that comes first; a wrong
// device_type is the less likely cause.
func explicitTypeHint(r resolvedType) string {
	return fmt.Sprintf("The device rejected the command syntax: the command, or its arguments, may not be valid on %s in this form. "+
		"If device_type=%s is not this device's platform, omit device_type to auto-detect it, or call detect_platform.", r.dt, r.dt)
}

// detectedRejectedNotice explains a rejected command after detection: the
// detected type may be wrong, so it was forgotten.
const detectedRejectedNotice = "The device rejected the command syntax. The detected device_type was forgotten, so the next call without device_type detects the platform again."

// detectedMismatchNotice explains a refused Linux SSH server after detection:
// the detected type no longer describes the server at that address, so it
// was forgotten rather than suggested for later calls.
const detectedMismatchNotice = "The detected device_type does not match this SSH server, so it was forgotten; the next call without device_type detects the platform again."

// afterRun inspects a command's outcome. A syntax error on a detected type
// drops the cached detection so the next call probes again; on an explicit
// type it yields a hint. A detected type whose server was refused as an
// unsupported platform (refuseLinuxServer) is dropped too, and is not
// suggested for later calls. It returns the notices to append to the result.
func afterRun(cfg sshclient.ConnConfig, r resolvedType, output string, runErr error) []mcp.Content {
	syntaxErr := rejectedSyntax(output, runErr)

	var notices []mcp.Content
	switch r.source {
	case sourceProbe, sourceCache:
		if errors.Is(runErr, errUnsupportedPlatform) {
			forgetType(cacheKey(cfg.Host, cfg.Port))
			return []mcp.Content{&mcp.TextContent{Text: detectedMismatchNotice}}
		}
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

// answer is an error that answers the call rather than reporting a failure
// of the device or the connection, such as a vdom the device does not list
// or output FortiOS paged. Such errors are logged at Info, and returned
// without detection notices, which have nothing to do with them. Make them
// with newAnswer where they arise.
type answer struct{ msg string }

func (a *answer) Error() string { return a.msg }

// newAnswer returns an error that answers the call (see answer).
func newAnswer(msg string) error { return &answer{msg: msg} }

// answerError reports whether err, or an error it wraps, is an answer.
func answerError(err error) bool {
	var a *answer
	return errors.As(err, &a)
}

// runError wraps a failed command, adding the same notice afterRun would
// have appended to a successful result.
func runError(ctx context.Context, tool string, cfg sshclient.ConnConfig, r resolvedType, err error) error {
	if requestCancelled(ctx) || answerError(err) {
		// The caller has gone, or the error answers the call: a detection
		// notice or hint means nothing.
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
