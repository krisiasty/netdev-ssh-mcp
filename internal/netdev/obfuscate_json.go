package netdev

import (
	"encoding/json"
	"slices"
	"strings"
)

// secretJSONKeyWords are the words that mark a JSON key as holding a secret.
// isSecretJSONKey matches them anywhere in a key, after lower-casing it and
// removing "-" and "_", so "snmpCommunity", "community-password",
// "shared_secret", "tacacsKey", "keyMaterial" and "md5Hash" all match. The
// plural "communities" does not contain "community", so it is listed
// separately. "key" and "md5" fail closed: a key name containing them is
// secret unless it is one of nonSecretJSONKeys.
var secretJSONKeyWords = []string{
	"password", "passwd", "passphrase", "secret", "community", "communities", "psk", "preshared",
	"privacy", "key", "md5",
}

// nonSecretJSONKeys are whole key names, after the same normalisation, that
// contain "key" but name a key's ID, key chain or algorithm rather than the
// key itself, so they stay readable for troubleshooting. Any other name
// containing "key" or "md5" is secret.
var nonSecretJSONKeys = []string{"keyid", "keychain", "keychainname", "keytype", "keyalgorithm"}

var jsonKeySeparators = strings.NewReplacer("-", "", "_", "")

// isSecretJSONKey reports whether a JSON object key names a secret value.
func isSecretJSONKey(key string) bool {
	k := jsonKeySeparators.Replace(strings.ToLower(key))
	return !slices.Contains(nonSecretJSONKeys, k) &&
		slices.ContainsFunc(secretJSONKeyWords, func(w string) bool { return strings.Contains(k, w) })
}

// decodeJSONKey returns the text of the quoted JSON string quoted with its
// escapes decoded, so an escaped key such as "pa\u0073sword" is classified
// as the "password" it is. A string that does not decode, such as one with an
// invalid escape, is returned without its quotes as written. Only a string
// with a backslash has escapes, so any other is returned without decoding,
// and so is a single-quoted (Python) string.
func decodeJSONKey(quoted string) string {
	raw := quoted[1 : len(quoted)-1]
	if quoted[0] != '"' || !strings.Contains(raw, `\`) {
		return raw
	}
	var key string
	if err := json.Unmarshal([]byte(quoted), &key); err != nil {
		return raw
	}
	return key
}

// jsonSpans returns a span for every value of a secret key in JSON text, such
// as "net show ... json" or "| json" output. The line patterns cannot see
// these: a JSON value sits on its own line, after a quoted key, or spans
// several lines inside an array or object.
//
// Strings may also be single-quoted, as in the Python repr that some NCLU
// commands print, and Python's True, False and None count as literals.
//
// A secret string value is hashed on its raw contents, quotes kept; a secret
// number becomes a quoted token, so the output stays valid JSON. Inside a
// secret array or object, every string, keys included (some platforms key
// communities by name), and every number, NaN and Infinity included, is
// hashed. A secret value is hashed whatever its form: a bare word that is not
// JSON, such as `"password": hunter2`, is hashed as well. Only the literals
// are left unchanged. Text that is not JSON passes through unless it contains
// the "key": value shape. No string spans lines, and a container walk hashes
// the first bare word that is not JSON and stops there, so a stray quote or
// bracket in plain text reaches no further than its own line or the next
// word.
func jsonSpans(text string) []span {
	r := &jsonScanner{text: text}
	for i := 0; i < len(text); {
		c := text[i]
		if c != '"' && c != '\'' {
			i++
			continue
		}
		end, closed := scanQuoted(text, i)
		if closed && r.isKey(end) && isSecretJSONKey(decodeJSONKey(text[i:end])) {
			colon := skipJSONSpace(text, end)
			i = r.value(skipJSONSpace(text, colon+1))
			continue
		}
		if c == '\'' {
			// Most single quotes in text are apostrophes, not strings: step
			// over this one alone, so that a key it would skip is still seen.
			i++
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
// past it. Only a literal is left alone.
func (r *jsonScanner) value(i int) int {
	if i >= len(r.text) {
		return i
	}
	switch r.text[i] {
	case '"', '\'':
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
// string is hashed to the end of its line. Empty strings are left alone.
func (r *jsonScanner) hashString(i int) (int, bool) {
	end, closed := scanQuoted(r.text, i)
	contents := end
	if closed {
		contents = end - 1
	}
	if contents > i+1 {
		r.add(i+1, contents, false)
	}
	return end, closed
}

// hashBareToken hashes the unquoted token text[i:end] unless it is a literal:
// true, false, null, or Python's True, False and None. A number is marked
// for a quoted token; NaN, Infinity and -Infinity count as numbers, since
// Python, and so NCLU, prints them bare. Any other word is hashed as it
// stands. It reports whether the token is a literal or a number in a JSON
// position, preceded by "[", ",", ":" or whitespace and followed by
// whitespace, ",", "]", "}" or the end of the text; only then can a
// container walk go on past it.
func (r *jsonScanner) hashBareToken(i, end int) bool {
	if end == i {
		return false
	}
	inPlace := (i == 0 || strings.IndexByte("[,: \t\r\n", r.text[i-1]) >= 0) &&
		(end == len(r.text) || strings.IndexByte(",]} \t\r\n", r.text[end]) >= 0)
	switch tok := r.text[i:end]; {
	case slices.Contains(jsonLiterals, tok):
		return inPlace
	case isJSONNumber(tok) || tok == "NaN" || tok == "Infinity" || tok == "-Infinity":
		r.add(i, end, true)
		return inPlace
	default:
		r.add(i, end, false)
		return false
	}
}

// jsonLiterals are the bare values that hold no secret.
var jsonLiterals = []string{"true", "false", "null", "True", "False", "None"}

// hashContainer walks the array or object that starts at i to its matching
// close bracket, hashing every string, number and word. It stops early, at
// the end of the text, an unterminated string, or just past a bare token that
// is not a JSON value, which it hashes, since what follows is not JSON. It returns the index where it
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
		case '"', '\'':
			end, closed := r.hashString(i)
			if !closed {
				return end
			}
			i = end
		default:
			end := bareTokenEnd(r.text, i)
			if !r.hashBareToken(i, end) {
				return end
			}
			i = end
		}
	}
	return i
}

// scanQuoted scans the string that starts at i and is quoted with text[i], a
// double quote or, in Python's repr, a single quote, honouring backslash
// escapes. It returns the index just past the closing quote and true, or, for
// an unterminated string, the index of the first unescaped newline or the end
// of the text and false. Neither form holds a raw newline, so a string never
// runs past its line.
func scanQuoted(text string, i int) (int, bool) {
	q := text[i]
	for j := i + 1; j < len(text); j++ {
		switch text[j] {
		case q:
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
