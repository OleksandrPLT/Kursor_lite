// Package dbmanager manages MySQL and PostgreSQL databases/users. The
// single chokepoint every generated CREATE DATABASE / CREATE USER /
// GRANT statement must pass through is ValidIdentifier — database and
// user names can't be bind-parameterized (placeholders only work for
// values, not object names), so a whitelist-then-quote discipline is
// the actual safety boundary. See identifier_test.go.
package dbmanager

import (
	"fmt"
	"regexp"
	"strings"
)

// identifierRe matches both MySQL's 64-char identifier limit and
// reasonable Postgres practice: must start with a letter, then
// letters/digits/underscore only. No backticks, quotes, dots,
// semicolons, whitespace, or anything else that would need escaping —
// if it doesn't match this, it's rejected outright rather than
// "escaped and hoped for the best".
var identifierRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

// ValidIdentifier is the whitelist check every database/user/role name
// must pass BEFORE it's ever interpolated into a DDL statement.
func ValidIdentifier(s string) error {
	if !identifierRe.MatchString(s) {
		return fmt.Errorf("invalid identifier %q: must start with a letter and contain only letters, digits, underscore (max 64 chars)", s)
	}
	return nil
}

// QuoteMySQL backtick-quotes an identifier already confirmed valid by
// ValidIdentifier. The backtick-doubling is defense in depth — the
// whitelist above already excludes backticks entirely — never a
// substitute for the whitelist check itself.
func QuoteMySQL(identifier string) string {
	return "`" + strings.ReplaceAll(identifier, "`", "``") + "`"
}

// QuotePostgres double-quotes an identifier already confirmed valid by
// ValidIdentifier, per the SQL standard's identifier-quoting convention.
func QuotePostgres(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

// QuoteMySQLString single-quotes a value for MySQL's CREATE USER
// 'name'@'host' string-literal syntax (usernames there are string
// literals, not backtick identifiers). Only ever called on a name
// already confirmed valid by ValidIdentifier — which forbids quote
// characters entirely — so the doubling below is defense in depth, not
// the actual safety boundary.
func QuoteMySQLString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
