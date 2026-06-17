package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"libvirt.org/go/libvirt"
)

const (
	domainGuestUserMetadataNamespace = "urn:devboxgateway:domain:guestuser"
	domainGuestUserMetadataPrefix    = "devboxgatewayguestuser"
)

type domainGuestUserMetadata struct {
	XMLName xml.Name `xml:"guestuser"`
	Value   string   `xml:",chardata"`
}

func domainGuestUserMetadataXML(guestUser string) (string, error) {
	guestUser = strings.TrimSpace(guestUser)
	if guestUser == "" {
		return "", fmt.Errorf("domain guest user metadata requires a non-empty user")
	}

	payload, err := xml.Marshal(domainGuestUserMetadata{Value: guestUser})
	if err != nil {
		return "", fmt.Errorf("marshal domain guest user metadata: %w", err)
	}
	return string(payload), nil
}

func setDomainGuestUserMetadata(dom *libvirt.Domain, guestUser string) error {
	payload, err := domainGuestUserMetadataXML(guestUser)
	if err != nil {
		return err
	}

	return dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		payload,
		domainGuestUserMetadataPrefix,
		domainGuestUserMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
}

func domainGuestUser(dom *libvirt.Domain) (string, bool, error) {
	payload, err := dom.GetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		domainGuestUserMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN_METADATA) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get domain guest user metadata: %w", err)
	}

	var metadata domainGuestUserMetadata
	if err := xml.Unmarshal([]byte(payload), &metadata); err != nil {
		return "", false, fmt.Errorf("parse domain guest user metadata: %w", err)
	}

	guestUser := strings.TrimSpace(metadata.Value)
	if guestUser == "" {
		return "", false, nil
	}
	return guestUser, true, nil
}
