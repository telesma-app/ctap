package protocol

import (
	"fmt"
	"strings"
)

type namedPermission struct {
	value Permission
	name  string
}

var namedPermissions = [...]namedPermission{
	{PermissionMakeCredential, "mc"},
	{PermissionGetAssertion, "ga"},
	{PermissionCredentialManagement, "cm"},
	{PermissionBioEnrollment, "be"},
	{PermissionLargeBlobWrite, "lbw"},
	{PermissionAuthenticatorConfiguration, "acfg"},
	{PermissionPersistentCredentialManagementReadOnly, "pcmr"},
}

// String returns the CTAP symbolic names of the permissions in p. Multiple
// permissions are returned in ascending bit order, separated by commas.
// Undefined permission bits are preserved as a hexadecimal suffix.
func (p Permission) String() string {
	if p == PermissionNone {
		return "none"
	}

	parts := make([]string, 0, len(namedPermissions)+1)

	known := PermissionNone
	for _, named := range namedPermissions {
		known |= named.value
		if p&named.value != 0 {
			parts = append(parts, named.name)
		}
	}

	if unknown := p &^ known; unknown != PermissionNone {
		parts = append(parts, fmt.Sprintf("unknown(0x%02x)", uint8(unknown)))
	}

	return strings.Join(parts, ",")
}
