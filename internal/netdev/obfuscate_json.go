package netdev

import (
	"slices"
	"strings"
)

// secretJSONKeyWords are the words that mark a JSON key as holding a secret.
// isSecretJSONKey matches them anywhere in a key, after lower-casing it and
// removing "-" and "_", so "snmpCommunity", "community-password" and
// "shared_secret" all match. The plural "communities" does not contain
// "community", so it is listed separately.
var secretJSONKeyWords = []string{
	"password", "passwd", "passphrase", "secret", "community", "communities", "psk", "preshared",
	"keystring", "authenticationkey", "authkey", "md5key", "privacy",
}

var jsonKeySeparators = strings.NewReplacer("-", "", "_", "")

// isSecretJSONKey reports whether a JSON object key names a secret value.
func isSecretJSONKey(key string) bool {
	k := jsonKeySeparators.Replace(strings.ToLower(key))
	return slices.ContainsFunc(secretJSONKeyWords, func(w string) bool { return strings.Contains(k, w) })
}

// obfuscateJSON hashes the values of secret keys in JSON text and reports
// whether it hashed any. obfuscate does not call it: it merges jsonSpans with
// the line pass's spans instead.
func obfuscateJSON(text string) (string, bool) {
	return hashSpans(text, jsonSpans(text))
}

// jsonSpans returns a span for every value of a secret key in JSON text, such
// as "net show ... json" or "| json" output. The line patterns cannot see
// these: a JSON value sits on its own line, after a quoted key, or spans
// several lines inside an array or object. A string that is already exactly
// a hash token is skipped, so obfuscated output is never hashed twice.
//
// A secret string value is hashed on its raw contents, quotes kept; a secret
// number becomes a quoted token, so the output stays valid JSON. Inside a
// secret array or object, every string, keys included (some platforms key
// communities by name), and every number, NaN and Infinity included, is
// hashed. true, false, null and all other text are unchanged. Text that is not JSON passes through unless it
// contains the "key": value shape. No string spans lines, and a container
// walk stops at the first thing that is not JSON, so a stray quote or bracket
// in plain text reaches no further than its own line or the next word.
func jsonSpans(text string) []span {
	r := &jsonScanner{text: text}
	for i := 0; i < len(text); {
		if text[i] != '"' {
			i++
			continue
		}
		end, closed := scanJSONString(text, i)
		if closed && r.isKey(end) && isSecretJSONKey(text[i+1:end-1]) {
			colon := skipJSONSpace(text, end)
			i = r.value(skipJSONSpace(text, colon+1))
			continue
		}
		i = end
	}
	return r.spans
}

// jsonScanner collects the secret spans jsonSpans finds in text.
type jsonScanner struct {
	text  string
	spans []span
}

func (r *jsonScanner) add(start, end int, number bool) {
	r.spans = append(r.spans, span{start: start, end: end, number: number})
}

// isKey reports whether the string that ends just before end is an object
// key: followed by optional whitespace, including newlines, and a colon.
func (r *jsonScanner) isKey(end int) bool {
	colon := skipJSONSpace(r.text, end)
	return colon < len(r.text) && r.text[colon] == ':'
}

// value hashes the secret value that starts at i and returns the index just
// past it. Anything other than a string, number, array or object is left
// alone.
func (r *jsonScanner) value(i int) int {
	if i >= len(r.text) {
		return i
	}
	switch r.text[i] {
	case '"':
		end, _ := r.hashString(i)
		return end
	case '[', '{':
		return r.hashContainer(i)
	default:
		end := bareTokenEnd(r.text, i)
		r.hashBareToken(i, end)
		return end
	}
}

// hashString hashes the contents of the string that starts at i and returns
// the index just past it and whether it was terminated. An unterminated
// string is hashed to the end of its line. Empty strings and strings that are
// already exactly a hash token are left alone.
func (r *jsonScanner) hashString(i int) (int, bool) {
	end, closed := scanJSONString(r.text, i)
	contents := end
	if closed {
		contents = end - 1
	}
	if s := r.text[i+1 : contents]; s != "" && !isHashToken(s) {
		r.add(i+1, contents, false)
	}
	return end, closed
}

// hashBareToken handles the unquoted token text[i:end]. It reports false when
// the token is not a JSON value in a JSON position: not true, false, null or
// a number, or not preceded by "[", ",", ":" or whitespace and followed by
// whitespace, ",", "]", "}" or the end of the text. A number is marked for a
// quoted token. NaN, Infinity and -Infinity count as numbers: Python, and so
// NCLU, prints them bare.
func (r *jsonScanner) hashBareToken(i, end int) bool {
	if end == i || (i > 0 && strings.IndexByte("[,: \t\r\n", r.text[i-1]) < 0) ||
		(end < len(r.text) && strings.IndexByte(",]} \t\r\n", r.text[end]) < 0) {
		return false
	}
	switch tok := r.text[i:end]; {
	case tok == "true" || tok == "false" || tok == "null":
		return true
	case isJSONNumber(tok) || tok == "NaN" || tok == "Infinity" || tok == "-Infinity":
		r.add(i, end, true)
		return true
	default:
		return false
	}
}

// hashContainer walks the array or object that starts at i to its matching
// close bracket, hashing every string and number. It stops early, at the end
// of the text, an unterminated string, or a bare token that is not a JSON
// value, since what follows is not JSON. It returns the index where it
// stopped, just past the close bracket on success.
func (r *jsonScanner) hashContainer(i int) int {
	depth := 0
	for i < len(r.text) {
		switch c := r.text[i]; c {
		case '[', '{':
			depth++
			i++
		case ']', '}':
			depth--
			i++
			if depth == 0 {
				return i
			}
		case ',', ':', ' ', '\t', '\r', '\n':
			i++
		case '"':
			end, closed := r.hashString(i)
			if !closed {
				return end
			}
			i = end
		default:
			end := bareTokenEnd(r.text, i)
			if !r.hashBareToken(i, end) {
				return i
			}
			i = end
		}
	}
	return i
}

// scanJSONString scans the double-quoted string that starts at i, honouring
// backslash escapes. It returns the index just past the closing quote and
// true, or, for an unterminated string, the index of the first unescaped
// newline or the end of the text and false. JSON strings never hold a raw
// newline, so a string never runs past its line.
func scanJSONString(text string, i int) (int, bool) {
	for j := i + 1; j < len(text); j++ {
		switch text[j] {
		case '"':
			return j + 1, true
		case '\n':
			return j, false
		case '\\':
			if j+1 < len(text) && text[j+1] != '\n' {
				j++
			}
		}
	}
	return len(text), false
}

// skipJSONSpace returns the index of the first non-whitespace byte at or
// after i, or len(text).
func skipJSONSpace(text string, i int) int {
	for i < len(text) && strings.IndexByte(" \t\r\n", text[i]) >= 0 {
		i++
	}
	return i
}

// bareTokenEnd returns the end of the unquoted token that starts at i: the
// first whitespace, JSON punctuation or quote, or len(text).
func bareTokenEnd(text string, i int) int {
	for i < len(text) && strings.IndexByte(" \t\r\n,:[]{}\"", text[i]) < 0 {
		i++
	}
	return i
}

// isJSONNumber reports whether tok matches -?[0-9][0-9.eE+-]*.
func isJSONNumber(tok string) bool {
	tok = strings.TrimPrefix(tok, "-")
	if tok == "" || tok[0] < '0' || tok[0] > '9' {
		return false
	}
	return strings.Trim(tok, "0123456789.eE+-") == ""
}

// isHashToken reports whether s is exactly a token made by hashSecret:
// "[h:" followed by 12 lower-case hex digits and "]".
func isHashToken(s string) bool {
	if len(s) != 16 || !strings.HasPrefix(s, "[h:") || s[15] != ']' {
		return false
	}
	return strings.Trim(s[3:15], "0123456789abcdef") == ""
}
