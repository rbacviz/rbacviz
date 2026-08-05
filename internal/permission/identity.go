package permission

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// ParseIdentity accepts user:<name>, group:<name>, or
// serviceaccount:<namespace>:<name>.
func ParseIdentity(value string) (Identity, error) {
	prefix, remainder, found := strings.Cut(strings.TrimSpace(value), ":")
	if !found || remainder == "" {
		return Identity{}, fmt.Errorf("identity must be user:<name>, group:<name>, or serviceaccount:<namespace>:<name>")
	}
	switch strings.ToLower(prefix) {
	case "user":
		return Identity{Kind: snapshot.IdentityUser, Name: remainder}, nil
	case "group":
		return Identity{Kind: snapshot.IdentityGroup, Name: remainder}, nil
	case "serviceaccount", "sa":
		namespace, name, ok := strings.Cut(remainder, ":")
		if !ok || namespace == "" || name == "" {
			return Identity{}, fmt.Errorf("service account identity must be serviceaccount:<namespace>:<name>")
		}
		return Identity{Kind: snapshot.IdentityServiceAccount, Namespace: namespace, Name: name}, nil
	default:
		return Identity{}, fmt.Errorf("unknown identity kind %q; use user, group, or serviceaccount", prefix)
	}
}

// String returns the canonical CLI representation of an identity.
func (identity Identity) String() string {
	switch identity.Kind {
	case snapshot.IdentityUser:
		return "user:" + identity.Name
	case snapshot.IdentityGroup:
		return "group:" + identity.Name
	case snapshot.IdentityServiceAccount:
		return "serviceaccount:" + identity.Namespace + ":" + identity.Name
	default:
		return strings.ToLower(string(identity.Kind)) + ":" + identity.Name
	}
}

func identityFromSubject(subject snapshot.Subject) Identity {
	return Identity{Kind: subject.Kind, Namespace: subject.Namespace, Name: subject.Name}
}

func subjectFromIdentity(identity Identity) snapshot.Subject {
	return snapshot.Subject{Kind: identity.Kind, Namespace: identity.Namespace, Name: identity.Name}
}

func identityKey(identity Identity) string {
	return strings.Join([]string{string(identity.Kind), identity.Namespace, identity.Name}, "\x00")
}

func subjectKey(subject snapshot.Subject) string {
	return identityKey(identityFromSubject(subject))
}

func canonicalGroups(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	sort.Strings(result)
	return dedupeStrings(result)
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] != values[write-1] {
			values[write] = values[read]
			write++
		}
	}
	return values[:write]
}
