package internal

import (
	"github.com/hashicorp/go-hclog"
	"slices"
	"testing"
)

func TestLocalSSHFetcher_convertToJson(t *testing.T) {
	fetcher := NewLocalSSHFetcher(hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Error,
		JSONFormat: true,
	}), map[string]string{})

	output, err := fetcher.convertToJson([]byte(`
port 22
listenaddress [::]:22
listenaddress 0.0.0.0:22
permitrootlogin without-password
pubkeyauthentication yes
passwordauthentication yes
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
	`))

	if err != nil {
		t.Error(err)
	}

	out := output["port"].([]string)
	if !slices.Contains(out, "22") {
		t.Errorf("Output not correctly processed")
	}
}
