package llm

import "testing"

// A transient rate-limit code must classify as rate_limit even when the message
// reads like quota exhaustion — the misclassification that paused scans for the
// full rate-limit wait budget instead of failing over to another pooled key.
func TestClassifyErrorString_StructuredCodeAuthoritative(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want ErrorClass
	}{
		{
			name: "rate_limit_error code with quota-ish message stays rate_limit",
			raw:  `429 Too Many Requests {"error":{"code":"rate_limit_error","message":"usage limit reached, please slow down and retry"}}`,
			want: ErrorClassRateLimit,
		},
		{
			name: "tokens (TPM) code is rate_limit",
			raw:  `{"error":{"code":"tokens","message":"tokens per minute exceeded"}}`,
			want: ErrorClassRateLimit,
		},
		{
			name: "requests (RPM) code is rate_limit",
			raw:  `{"error":{"code":"requests","message":"requests per minute exceeded"}}`,
			want: ErrorClassRateLimit,
		},
		{
			name: "genuine insufficient_quota code stays quota_exhausted",
			raw:  `{"error":{"code":"insufficient_quota","message":"account balance is too low"}}`,
			want: ErrorClassQuotaExhausted,
		},
		{
			name: "billing_not_active code is quota_exhausted",
			raw:  `{"error":{"code":"billing_not_active","message":"billing disabled"}}`,
			want: ErrorClassQuotaExhausted,
		},
		{
			name: "no structured code: genuine quota phrase still classifies as quota",
			raw:  `Error: credit balance is too low to continue`,
			want: ErrorClassQuotaExhausted,
		},
		{
			name: "no structured code: plain 429 still classifies as rate_limit",
			raw:  `HTTP 429: too many requests, retry after 5s`,
			want: ErrorClassRateLimit,
		},
	}
	for _, tc := range cases {
		if got := ClassifyErrorString(tc.raw).Class; got != tc.want {
			t.Errorf("%s: ClassifyErrorString().Class = %q, want %q", tc.name, got, tc.want)
		}
	}
}
