package singproxy

import (
	"errors"
	"strings"
	"testing"
)

// outboundCreationError reports whether err comes from sing-box telling
// us that an optional feature was left out of this build. Tests that
// exercise such features should skip instead of failing.
func outboundCreationError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not included in this build")
}

func skipIfFeatureMissing(t *testing.T, err error) {
	t.Helper()
	if err != nil && outboundCreationError(err) {
		t.Skipf("optional feature not in this build: %v", err)
	}
}

var _ = errors.Is
