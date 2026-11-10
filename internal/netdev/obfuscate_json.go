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

// obfuscateJSON hashes the values of secret keys in JSON text, such as
// "net show ... json" or "| json" output, and reports whether it hashed any.
// The line patterns cannot see these: a JSON value sits on its own line,
// after a quoted key, or spans several lines inside an array or object.
//
// A secret string value is hashed on its raw contents, quotes kept; a secret
// number becomes a quoted token, so the output stays valid JSON. Inside a
// secret array or object, every string that is not itself a key and every
// number is hashed. true, false, null and all other text are unchanged.
// Text that is not JSON passes through unless it contains the
// "key": value shape. Malformed input is hashed as far as it goes: an
// unterminated secret value is hashed to the end of the text.
func obfuscateJSON(text string) (string, bool) {
	r := &jsonRewriter{text: text}
	for i := 0; i < len(text); {
		if text[i] != '"' {
			i++
			continue
		}
		// A key never spans lines, so a stray quote costs at most one line.
		end, closed := scanJSONString(text, i, true)
		if closed && r.isKey(end) && isSecretJSONKey(text[i+1:end-1]) {
			colon := skipJSONSpace(text, end)
			i = r.value(skipJSONSpace(text, colon+1))
			continue
		}
		i = end
	}
	if !r.hashed {
		return text, false
	}
	r.b.WriteString(text[r.prev:])
	return r.b.String(), true
}

// jsonRewriter builds the output of obfuscateJSON: text with replacements
// applied in increasing order of position.
type jsonRewriter struct {
	text   string
	b      strings.Builder
	prev   int // end of the last replacement; text before it is written
	hashed bool
}

func (r *jsonRewriter) replace(start, end int, repl string) {
	r.b.WriteString(r.text[r.prev:start])
	r.b.WriteString(repl)
	r.prev = end
	r.hashed = true
}

// isKey reports whether the string that ends just before end is an object
// key: followed by optional whitespace, including newlines, and a colon.
func (r *jsonRewriter) isKey(end int) bool {
	colon := skipJSONSpace(r.text, end)
	return colon < len(r.text) && r.text[colon] == ':'
}

// value hashes the secret value that starts at i and returns the index just
// past it. Anything other than a string, number, array or object is left
// alone.
func (r *jsonRewriter) value(i int) int {
	if i >= len(r.text) {
		return i
	}
	switch r.text[i] {
	case '"':
		return r.hashString(i)
	case '[', '{':
		return r.hashContainer(i)
	default:
		return r.hashNumber(i)
	}
}

// hashString hashes the contents of the string that starts at i, or of
// everything after its opening quote when it is unterminated, and returns the
// index just past it. Empty strings are left alone.
func (r *jsonRewriter) hashString(i int) int {
	end, closed := scanJSONString(r.text, i, false)
	contents := end
	if closed {
		contents = end - 1
	}
	if contents > i+1 {
		r.replace(i+1, contents, hashSecret(r.text[i+1:contents]))
	}
	return end
}

// hashNumber replaces the number that starts at i with a quoted token and
// returns the index just past it, or returns i unchanged when no number
// starts there.
func (r *jsonRewriter) hashNumber(i int) int {
	end := jsonNumberEnd(r.text, i)
	if end > i {
		r.replace(i, end, `"`+hashSecret(r.text[i:end])+`"`)
	}
	return end
}

// hashContainer walks the array or object that starts at i to its matching
// close bracket, or to the end of the text, hashing every string that is not
// a key and every number. It returns the index just past the close bracket.
func (r *jsonRewriter) hashContainer(i int) int {
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
		case '"':
			end, closed := scanJSONString(r.text, i, false)
			if closed && r.isKey(end) {
				i = end
				continue
			}
			i = r.hashString(i)
		default:
			if end := r.hashNumber(i); end > i {
				i = end
				continue
			}
			i++
		}
	}
	return i
}

// scanJSONString scans the double-quoted string that starts at i, honouring
// backslash escapes. It returns the index just past the closing quote and
// true, or, for an unterminated string, the end of the text (or, when
// stopAtNewline is set, the index of the first unescaped newline) and false.
func scanJSONString(text string, i int, stopAtNewline bool) (int, bool) {
	for j := i + 1; j < len(text); j++ {
		switch text[j] {
		case '"':
			return j + 1, true
		case '\n':
			if stopAtNewline {
				return j, false
			}
		case '\\':
			if j+1 < len(text) && (!stopAtNewline || text[j+1] != '\n') {
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

// jsonNumberEnd returns the end of the number matching -?[0-9][0-9.eE+-]*
// that starts at i, or i when none starts there.
func jsonNumberEnd(text string, i int) int {
	j := i
	if j < len(text) && text[j] == '-' {
		j++
	}
	if j >= len(text) || text[j] < '0' || text[j] > '9' {
		return i
	}
	for j < len(text) && strings.IndexByte("0123456789.eE+-", text[j]) >= 0 {
		j++
	}
	return j
}
