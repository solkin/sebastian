package gateway

import (
	"net/http"
	"strings"
)

// requestLogURL strips bearer credentials without changing the request used by
// authentication. Operational query parameters such as uploadId remain useful.
func requestLogURL(r *http.Request) string {
	u := *r.URL
	u.User = nil
	q := u.Query()
	for key := range q {
		switch strings.ToLower(key) {
		case "x-amz-algorithm", "x-amz-credential", "x-amz-date", "x-amz-expires",
			"x-amz-security-token", "x-amz-signature", "x-amz-signedheaders",
			"awsaccesskeyid", "signature", "securitytoken":
			q.Del(key)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
