package ui

import (
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// apiStatus passes the API server's own HTTP code through to the browser, so a
// capture the operator's role is not allowed to create says 403 in the page and
// not "internal error".
func apiStatus(err error) int {
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		return int(status.Status().Code)
	}
	return 0
}
