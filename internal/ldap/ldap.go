package ldap

import (
	"crypto/tls"
	"fmt"
	"log"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/types"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func LdapAuthenticateAccess(username, password string, settings *config.SettingsType) (*types.User, error) {
	conn, err := dialLDAP(settings)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	userMailDomain := settings.Get(config.LDAP_USER_DOMAIN)
	ntlmFallback := strings.TrimSpace(settings.Get(config.NTLM_DOMAIN))
	if ntlmFallback == "" {
		ntlmFallback = userMailDomain
	}
	normalizedUser, ntlmDomain := splitNTLMUserDomain(username, ntlmFallback)
	if normalizedUser == "" {
		normalizedUser = username
	}
	log.Printf("NTLM login mapping: input=%q user=%q domain=%q", username, normalizedUser, ntlmDomain)

	mail := username
	if !strings.Contains(username, "@") && userMailDomain != "" {
		domain := userMailDomain
		if !strings.HasPrefix(domain, "@") {
			domain = "@" + domain
		}
		mail = username + domain
	}

	// Bind as the user using only the mail/UPN form.
	bindIDs := []string{mail}

	var bindErr error
	for _, id := range bindIDs {
		if id == "" {
			continue
		}
		if err := conn.Bind(id, password); err == nil {
			bindErr = nil
			break
		} else {
			bindErr = err
		}
	}
	if bindErr != nil {
		return nil, fmt.Errorf("ldap bind failed: %w", bindErr)
	}

	userFilter := settings.Get(config.LDAP_USER_FILTER)
	baseDN := settings.Get(config.LDAP_BASE_DN)

	filter := fmt.Sprintf(userFilter, mail)
	fmt.Println("filter", filter)
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 1, 0, false,
		filter,
		nil,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user %s not found", mail)
	}

	return types.NewUser(normalizedUser, password, ntlmDomain)
}

func dialLDAP(settings *config.SettingsType) (*ldap.Conn, error) {

	// #nosec G402 -- skip TLS verification if configured
	ldapUrl := settings.Get(config.LDAP_URL)
	insecureSkipVerify := settings.IsTrue(config.LDAP_SKIP_TLS_VERIFY)
	startTLS := settings.IsTrue(config.LDAP_STARTTLS)

	conn, err := ldap.DialURL(ldapUrl, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: insecureSkipVerify}))
	if err != nil {
		return nil, err
	}

	if startTLS && strings.HasPrefix(ldapUrl, "ldap://") {
		// #nosec G402 -- skip TLS verification if configured
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: insecureSkipVerify}); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func splitNTLMUserDomain(username, fallbackDomain string) (string, string) {
	user := strings.TrimSpace(username)
	if user == "" {
		return "", ""
	}
	if idx := strings.LastIndex(user, "\\"); idx >= 0 {
		domain := strings.TrimSpace(user[:idx])
		trimmed := strings.TrimSpace(user[idx+1:])
		if trimmed != "" {
			return trimmed, domain
		}
	}
	if idx := strings.LastIndex(user, "@"); idx >= 0 {
		domain := strings.TrimSpace(user[idx+1:])
		trimmed := strings.TrimSpace(user[:idx])
		if trimmed != "" {
			return trimmed, domain
		}
	}
	fallback := strings.TrimSpace(fallbackDomain)
	fallback = strings.TrimPrefix(fallback, "@")
	return user, fallback
}
