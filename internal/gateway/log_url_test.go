package gateway

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAccessLogRedactsPresignedCredentialsWithoutChangingRequest(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var log bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&log, nil))
			req := httptest.NewRequest("GET", "https://user:password@example.com/bucket/file?X-Amz-Credential=private-access&X-Amz-Signature=private-signature&x-aMz-sIgNaTuRe=second-signature&X-Amz-Security-Token=private-session&AWSAccessKeyId=legacy-access&Signature=legacy-signature&SecurityToken=legacy-session&uploadId=visible&partNumber=3", nil)
			original := req.URL.String()
			handler := LogMiddleware(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			handler.ServeHTTP(httptest.NewRecorder(), req)
			var record map[string]any
			if err := json.Unmarshal(log.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			logged := record["url"].(string)
			for _, secret := range []string{"password", "private-access", "private-signature", "second-signature", "private-session", "legacy-access", "legacy-signature", "legacy-session"} {
				if strings.Contains(logged, secret) {
					t.Fatalf("credential leaked in access log: %s", logged)
				}
			}
			u, err := url.Parse(logged)
			if err != nil || u.Path != "/bucket/file" || u.Query().Get("uploadId") != "visible" || u.Query().Get("partNumber") != "3" {
				t.Fatalf("lost operational URL: %s %v", logged, err)
			}
			if req.URL.String() != original {
				t.Fatal("logger changed signed request")
			}
		})
	}
}
