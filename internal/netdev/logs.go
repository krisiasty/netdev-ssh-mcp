package netdev

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

// logUnits lists, per platform, the systemd units get_logs may read. Only
// Linux-based platforms have any; get_logs refuses every other platform. The
// unit is inserted into a bash command line, so only names listed here are
// ever sent.
var logUnits = map[deviceType][]string{
	deviceTypeCumulus4x: {"clagd", "frr", "mstpd", "ptmd", "switchd"},
}

const (
	// defaultLogSince is the --since value when the caller gives none.
	defaultLogSince = "-1h"
	// defaultLogLines is the --lines value when the caller gives none. A
	// day of switchd on a quiet switch is megabytes, which would use much of
	// an agent's context and exceed MCP clients' output limits, so an
	// unlimited default is not useful.
	defaultLogLines = 1000
	// maxLogLines is the largest --lines value get_logs accepts.
	maxLogLines = 100000
	// maxLogSinceLen bounds since, which the patterns below already keep
	// short, so a long value is refused before any regexp runs.
	maxLogSinceLen = 64
)

// logSinceRelativeRe matches a relative --since value: a "-" and one or more
// numbers each followed by a systemd time-span unit, such as -15min, -1h or
// -1h30min. Only the units up to weeks are accepted; systemd reads "m" as
// minutes.
var logSinceRelativeRe = regexp.MustCompile(`^-(?:[0-9]{1,6}(?:s|sec|second|seconds|m|min|minute|minutes|h|hour|hours|d|day|days|w|week|weeks))+$`)

// logSinceAbsoluteLayouts are the absolute --since forms accepted, as Go
// time layouts, which also reject impossible dates such as 2026-02-30.
// journalctl reads them in the device's local timezone.
var logSinceAbsoluteLayouts = []string{
	"2006-01-02",
	"2006-01-02 15:04",
	"2006-01-02 15:04:05",
}

// logSinceAbsoluteRe matches the shape of logSinceAbsoluteLayouts, which
// time.Parse alone does not pin down (it accepts single-digit hours).
var logSinceAbsoluteRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}(?: [0-9]{2}:[0-9]{2}(?::[0-9]{2})?)?$`)

// logSinceKeywords are the systemd timestamp keywords accepted for --since.
var logSinceKeywords = []string{"today", "yesterday"}

const logSinceRule = "a relative time such as -15min, -1h, -2d or -1h30min (units s, sec, m, min, h, hour, d, day, w, week, and their plurals), " +
	"'today', 'yesterday', or a device-local date and time as YYYY-MM-DD, YYYY-MM-DD HH:MM or YYYY-MM-DD HH:MM:SS"

// normalizeLogSince checks since and returns it trimmed, or defaultLogSince
// when it is empty. The value is single-quoted in the command, so every
// accepted form must be free of quotes; none of them has any character bash
// treats specially inside single quotes.
func normalizeLogSince(since string) (string, error) {
	since = strings.TrimSpace(since)
	if since == "" {
		return defaultLogSince, nil
	}
	if len(since) > maxLogSinceLen {
		return "", fmt.Errorf("since must be %s", logSinceRule)
	}
	if slices.Contains(logSinceKeywords, since) || logSinceRelativeRe.MatchString(since) {
		return since, nil
	}
	if logSinceAbsoluteRe.MatchString(since) {
		for _, layout := range logSinceAbsoluteLayouts {
			if len(layout) != len(since) {
				continue
			}
			if _, err := time.Parse(layout, since); err != nil {
				return "", fmt.Errorf("since %q is not a valid date and time", since)
			}
			return since, nil
		}
	}
	return "", fmt.Errorf("since must be %s", logSinceRule)
}

// normalizeLogLines checks lines and returns it, or defaultLogLines when it
// is 0 (omitted).
func normalizeLogLines(lines int) (int, error) {
	if lines < 0 || lines > maxLogLines {
		return 0, fmt.Errorf("lines must be between 1 and %d, or omitted for the default of %d", maxLogLines, defaultLogLines)
	}
	if lines == 0 {
		return defaultLogLines, nil
	}
	return lines, nil
}

// logPlatforms lists the platforms that have log units, sorted.
func logPlatforms() []deviceType {
	return slices.Sorted(maps.Keys(logUnits))
}

// logPlatformsText names the platforms that have log units, for messages.
func logPlatformsText() string {
	names := make([]string, 0, len(logUnits))
	for _, dt := range logPlatforms() {
		names = append(names, string(dt))
	}
	return strings.Join(names, ", ")
}

// errNoLogUnits refuses get_logs on a platform without log units.
func errNoLogUnits(dt deviceType) error {
	return fmt.Errorf("get_logs supports no log units on %s; it reads logs only on %s", dt, logPlatformsText())
}

// checkLogUnitOnAnyPlatform rejects a unit that no platform allows, so it
// fails before detection logs in to the device. The platform's own list is
// checked once the type is known.
func checkLogUnitOnAnyPlatform(unit string) error {
	if unit == "" {
		return fmt.Errorf("unit is required; call list_log_units for the units of a platform")
	}
	for _, units := range logUnits {
		if slices.Contains(units, unit) {
			return nil
		}
	}
	return fmt.Errorf("unit %q is not allowed; %s", unit, logUnitsSummary())
}

// logUnitsSummary lists the units of every platform, for messages.
func logUnitsSummary() string {
	parts := make([]string, 0, len(logUnits))
	for _, dt := range logPlatforms() {
		parts = append(parts, fmt.Sprintf("%s: %s", dt, strings.Join(logUnits[dt], ", ")))
	}
	return "allowed units are " + strings.Join(parts, "; ")
}

// buildLogsCommand builds the journalctl command for unit on dt. since must
// have passed normalizeLogSince and lines normalizeLogLines; the unit is checked
// against dt's list here. Every platform in logUnits is Linux, where bash
// runs the command, so stderr is merged as on Cumulus Linux and since, which
// can hold a space, is single-quoted.
func buildLogsCommand(dt deviceType, unit, since string, lines int) (string, error) {
	if dt == "" {
		return "", errDeviceTypeUnresolved
	}
	units, ok := logUnits[dt]
	if !ok {
		return "", errNoLogUnits(dt)
	}
	if !slices.Contains(units, unit) {
		return "", fmt.Errorf("unit %q is not allowed on %s; allowed units are %s", unit, dt, strings.Join(units, ", "))
	}
	if strings.ContainsRune(since, '\'') {
		// normalizeLogSince accepts no quote; this guards the quoting below.
		return "", fmt.Errorf("since must not contain quotes")
	}
	if lines <= 0 || lines > maxLogLines {
		return "", fmt.Errorf("lines %d is out of range", lines)
	}
	parts := []string{"journalctl", "-u", unit, "--since", "'" + since + "'", "--lines", fmt.Sprintf("%d", lines), "--no-pager"}
	return strings.Join(parts, " ") + cumulusMergeStderr, nil
}

// journalNoAccessRe matches the hint journalctl prints when the account
// cannot read the system journal. Log entries start with a timestamp, so they
// cannot match it.
var journalNoAccessRe = regexp.MustCompile(`(?m)^Hint: You are currently not seeing messages from other users and the system`)

// journalNoAccessNotice explains journalNoAccessRe's hint.
const journalNoAccessNotice = "journalctl reports that this account cannot read the system journal, so the output above holds only its own messages, " +
	"if any: add the account to the systemd-journal group on the device."

// journalNoFilesRe matches the error journalctl prints, after the hint, when
// the account cannot open any journal file; it then exits with status 1.
var journalNoFilesRe = regexp.MustCompile(`(?m)^No journal files were opened due to insufficient permissions`)

// journalNoFilesNotice explains journalNoFilesRe's error.
const journalNoFilesNotice = "journalctl could not open any journal file because this account cannot read the system journal: " +
	"add the account to the systemd-journal group on the device."

// journalAccessNotice returns the notice for journalctl output that shows the
// account cannot read the system journal, or "".
func journalAccessNotice(out string) string {
	switch {
	case journalNoFilesRe.MatchString(out):
		return journalNoFilesNotice
	case journalNoAccessRe.MatchString(out):
		return journalNoAccessNotice
	}
	return ""
}

// countLogEntries counts the journal entries in journalctl output: lines
// that are not empty, not journalctl's own "-- ... --" markers (the header,
// "-- No entries --", "-- Reboot --"), not its hint, and not indented
// continuations of a multi-line entry or the hint.
func countLogEntries(out string) int {
	n := 0
	for line := range strings.SplitSeq(out, "\n") {
		switch {
		case line == "", strings.HasPrefix(line, "-- "), strings.HasPrefix(line, "Hint: "),
			strings.HasPrefix(line, " "), strings.HasPrefix(line, "\t"):
			continue
		}
		n++
	}
	return n
}

// logsNotices returns the notices to append to get_logs output for a call
// with the given lines limit.
func logsNotices(out string, lines int) []mcp.Content {
	var notices []mcp.Content
	if notice := journalAccessNotice(out); notice != "" {
		notices = append(notices, &mcp.TextContent{Text: notice})
	}
	entries := countLogEntries(out)
	if entries >= lines {
		notices = append(notices, &mcp.TextContent{Text: fmt.Sprintf(
			"journalctl returned the newest %d entries, the lines limit, so older entries in the time window were probably left out; "+
				"narrow since, or raise lines (up to %d) to get more.", lines, maxLogLines)})
	}
	if entries > defaultLogLines {
		notices = append(notices, &mcp.TextContent{Text: fmt.Sprintf(
			"Warning: this result holds %d log entries (%d bytes), more than the default of %d. A result this large uses much of "+
				"an agent's context and may exceed an MCP client's output limit; narrow since or lower lines if you need less.",
			entries, len(out), defaultLogLines)})
	}
	return notices
}

// logsErrorLines is how much of a failed journalctl's output is reported.
const logsErrorLines = 20

// logsCommandError adds the start of the device output to the error of a
// failed journalctl, which states the reason only there ("Failed to parse
// timestamp", "No journal files were opened due to insufficient
// permissions"), and the journalAccessNotice that applies. The output may
// hold log entries, so all of it is obfuscated before the first
// logsErrorLines lines are taken, and it is left out if that fails.
// Call it after logging, so the output stays out of the log.
func logsCommandError(err error) error {
	var cmdErr *sshclient.CommandError
	if !errors.As(err, &cmdErr) {
		return err
	}
	// Obfuscate before cutting: a pattern that spans lines, such as a PEM
	// private key block, needs both of its ends to match.
	out, _, obfErr := obfuscate(string(cmdErr.Output))
	if obfErr != nil {
		return err
	}
	out = strings.TrimSpace(firstLines(out, logsErrorLines))
	if out == "" {
		return err
	}
	if notice := journalAccessNotice(string(cmdErr.Output)); notice != "" {
		return fmt.Errorf("%w; device output:\n%s\n%s", err, out, notice)
	}
	return fmt.Errorf("%w; device output:\n%s", err, out)
}

// GetLogsInput defines the input parameters for the get_logs tool.
type GetLogsInput struct {
	Host       string `json:"host"       jsonschema:"hostname or IP address of the switch"`
	Unit       string `json:"unit"       jsonschema:"systemd unit to read the journal of, one of those list_log_units returns for the platform (cumulus4x: clagd, frr, mstpd, ptmd, switchd)"`
	Since      string `json:"since,omitempty" jsonschema:"start of the time window, defaults to -1h: a relative time such as -15min, -1h, -2d or -1h30min, 'today', 'yesterday', or a device-local YYYY-MM-DD, YYYY-MM-DD HH:MM or YYYY-MM-DD HH:MM:SS"`
	Lines      int    `json:"lines,omitempty" jsonschema:"return at most the newest N entries of the window, 1 to 100000, defaults to 1000; the result says when the limit was reached, and warns when it holds more than 1000 entries, which uses much of an agent's context and may exceed an MCP client's output limit"`
	Username   string `json:"username,omitempty" jsonschema:"SSH username; if omitted, falls back to the DEVICE_USERNAME environment variable"`
	Port       int    `json:"port,omitempty" jsonschema:"SSH port, defaults to 22"`
	DeviceType string `json:"device_type,omitempty" jsonschema:"device OS type; only cumulus4x (Cumulus Linux 4.x) has log units; if omitted, the platform is auto-detected over SSH and reported in the result"`
}

// GetLogs returns the systemd journal of an allowed unit on a Linux-based
// switch.
func GetLogs(ctx context.Context, req *mcp.CallToolRequest, args GetLogsInput) (*mcp.CallToolResult, any, error) {
	if args.Host == "" {
		return nil, nil, fmt.Errorf("host is required")
	}
	if args.Username == "" {
		args.Username = os.Getenv("DEVICE_USERNAME")
	}
	if args.Username == "" {
		return nil, nil, fmt.Errorf("username is required: pass it as a parameter or set DEVICE_USERNAME")
	}
	// Reject bad arguments before detection opens a connection.
	unit := strings.TrimSpace(args.Unit)
	if err := checkLogUnitOnAnyPlatform(unit); err != nil {
		return nil, nil, err
	}
	since, err := normalizeLogSince(args.Since)
	if err != nil {
		return nil, nil, err
	}
	lines, err := normalizeLogLines(args.Lines)
	if err != nil {
		return nil, nil, err
	}

	cfg, rt, err := resolveTarget(ctx, args.Host, args.Port, args.Username, args.DeviceType)
	if err != nil {
		return nil, nil, fmt.Errorf("get_logs: %w", err)
	}
	command, err := buildLogsCommand(rt.dt, unit, since, lines)
	if err != nil {
		if rt.source != sourceExplicit {
			return nil, nil, fmt.Errorf("%w (device_type %s was auto-detected)", err, rt.dt)
		}
		return nil, nil, err
	}

	slog.Info("get_logs", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "cmd", sanitizeLog(command)) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	out, err := runOn(ctx, cfg, rt, "", []string{command})
	if err != nil {
		logFailure(ctx, "get_logs", err, "host", args.Host, "unit", unit)
		return nil, nil, runError(ctx, "get_logs", cfg, rt, logsCommandError(err))
	}

	res, err := obfuscatedResult(out)
	if err != nil {
		return nil, nil, fmt.Errorf("get_logs: %w", err)
	}
	res.Content = append(res.Content, logsNotices(out, lines)...)
	res.Content = append(res.Content, afterRun(cfg, rt, out, nil)...)
	slog.Info("get_logs done", "host", args.Host, "bytes", len(out))
	return res, nil, nil
}

// ListLogUnitsInput defines the input parameters for the list_log_units
// tool.
type ListLogUnitsInput struct {
	Host       string `json:"host,omitempty" jsonschema:"hostname or IP address of the switch; required unless device_type is given, and then used to auto-detect the platform over SSH"`
	Username   string `json:"username,omitempty" jsonschema:"SSH username for auto-detection; if omitted, falls back to the DEVICE_USERNAME environment variable"`
	Port       int    `json:"port,omitempty" jsonschema:"SSH port for auto-detection, defaults to 22"`
	DeviceType string `json:"device_type,omitempty" jsonschema:"device OS type: eos, ios, nxos, junos, fortios or cumulus4x; when given, the units are listed without connecting to the device"`
}

// ListLogUnits lists the units get_logs may read on a platform: the one
// given as device_type, without connecting, or the one detected for host.
func ListLogUnits(ctx context.Context, req *mcp.CallToolRequest, args ListLogUnitsInput) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(args.DeviceType) != "" {
		dt, err := normalizeDeviceType(args.DeviceType)
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: logUnitsReport(dt)}},
		}, nil, nil
	}

	if args.Host == "" {
		return nil, nil, fmt.Errorf("host or device_type is required")
	}
	if args.Username == "" {
		args.Username = os.Getenv("DEVICE_USERNAME")
	}
	if args.Username == "" {
		return nil, nil, fmt.Errorf("username is required: pass it as a parameter or set DEVICE_USERNAME")
	}

	slog.Info("list_log_units", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username)) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	cfg, rt, err := resolveTarget(ctx, args.Host, args.Port, args.Username, "")
	if err != nil {
		return nil, nil, fmt.Errorf("list_log_units: %w", err)
	}
	return &mcp.CallToolResult{
		Content: slices.Concat([]mcp.Content{&mcp.TextContent{Text: logUnitsReport(rt.dt)}}, afterRun(cfg, rt, "", nil)),
	}, nil, nil
}

// logUnitsReport lists the units get_logs may read on dt.
func logUnitsReport(dt deviceType) string {
	units, ok := logUnits[dt]
	if !ok {
		return fmt.Sprintf("No log units on %s: get_logs reads logs only on %s.", dt, logPlatformsText())
	}
	return fmt.Sprintf("Log units get_logs can read on %s:\n%s\nPass one of these as unit to get_logs.", dt, strings.Join(units, "\n"))
}
