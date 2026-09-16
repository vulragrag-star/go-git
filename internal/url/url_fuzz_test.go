package url

import (
	"regexp"
	"testing"
)

// FuzzURLScanner is a differential target: it asserts that the
// hand-written scanners in url.go agree with the grammars they
// implement, on the match decision and on all three submatches, for any
// input. The SCP grammar is canonical Git's -- no port, and a bracketed
// literal host is a host -- not the regexp the scanners were first
// written against.
//
// Everything it needs is declared inside the function body on purpose.
// OSS-Fuzz does not run `go test -fuzz`: it strips this file down to its
// target bodies and compiles it without the package's other test files,
// so a target that reaches for a package-level helper builds locally and
// fails there. See tests/fuzz for the rules.
//
// The same two grammars are declared once more, at the top of
// scanner_equiv_test.go, where the deterministic sweeps use them. The
// seeds below keep the copies honest without anything comparing them:
// they cover each rule the grammars state, so a copy that drifts from
// the scanners disagrees on a seed and fails this target under plain
// `go test`, before any fuzzing.
func FuzzURLScanner(f *testing.F) {
	oracleScheme := regexp.MustCompile(`://`)
	oracleScp := regexp.MustCompile(`^(?:(?P<user>[^@]+)@)?(?P<host>\[[^\]\s]+\]|[^:\s]*):(?P<path>(?:[^\\].*)?)$`)

	for _, seed := range []string{
		"", ":", "://", "a://", "a://b", "a:b://c", "://a", "a:/b", "a:",
		"git@host:a://b", "/abs/a://b", "./foo://bar",
		"ssh://git@github.com/user/repository.git",
		"http://git:pass@github.com:8080/user/repository.git?foo#bar",
		"a@b:c", "a@b@c:d", "@host:p", "a@:path", "a@@b:c", "@:p", "a@b",
		":", "a@:", "[a]:", "@:",
		"host:path", ":path", "host:", "ho st:path", "ho\tst:path",
		"ho\nst:path", "ho\rst:path", "ho\fst:path", "ho\vst:path",
		"ho\x00st:path", "ho\xffst:path", "h\xc3\xa9st:path",
		"h:22:p", "h:0:p", "h:99999:p", "h:123456:p", "h:22:", "h:22:\\p",
		"h:007/bond", "h::p", "h:2a:p",
		"h:\\p", "h:p\nq", "h:p\n", "h:\np", "h:\n", "h:\\", "h:p\\q",
		"[fe80::1]:repo.git", "git@[fe80::1]:repo.git", "[fe80::1]:22:repo.git",
		"[a:b]:c", "[a:b]:\\c", "[a]:c", "[a]:", "[]:p", "[:p", "[a:c",
		"[a]x:c", "[a b]:c", "[a]::c", "a@[b]:c", "[a@b]:c", "[[a]:c",
		"h:\xc3\xa9p", "h:\xc3\xa9\n",
		"git@github.com:james/bond", "git@github.com:22:james/bond",
		"git@github.com:22:007/bond", "git@github.com:_james/bond.git",
		"git@[fe80::1]:james/bond",
		"user@host.example.com:path/to/repo.git",
		"/abs/path/with:colon/file", "./relative:path", "sub/dir:foo",
		"C:foo", "C:/path/to/repo", "C:\\path\\to\\repo", "d:relative",
		"/foo.git", "foo.git", "file:///foo.git", "file://C:/path/to/repo",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, endpoint string) {
		if got, want := MatchesScheme(endpoint), oracleScheme.MatchString(endpoint); got != want {
			t.Fatalf("MatchesScheme(%q) = %v, regexp says %v", endpoint, got, want)
		}

		user, host, path, ok := matchScpLike(endpoint)
		m := oracleScp.FindStringSubmatch(endpoint)
		if ok != (m != nil) {
			t.Fatalf("matchScpLike(%q) ok = %v, regexp says %v", endpoint, ok, m != nil)
		}
		if !ok {
			return
		}
		if user != m[1] || host != m[2] || path != m[3] {
			t.Fatalf("matchScpLike(%q) = (user=%q host=%q path=%q), regexp = (user=%q host=%q path=%q)",
				endpoint, user, host, path, m[1], m[2], m[3])
		}
	})
}
