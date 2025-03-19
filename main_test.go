package main

import (
	"context"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"testing"
)

type TestSSHFetcher struct {
	logger hclog.Logger
	config map[string]string
}

func NewTestSSHFetcher(logger hclog.Logger, config map[string]string) *TestSSHFetcher {
	return &TestSSHFetcher{
		logger: logger,
		config: config,
	}
}

func (l *TestSSHFetcher) FetchSSHConfiguration(ctx context.Context) (map[string]interface{}, []*proto.Step, error) {
	steps := make([]*proto.Step, 0)

	return map[string]interface{}{
		"authorizedkeysfile": []string{
			".ssh/authorized_keys",
			".ssh/authorized_keys2",
		},
		"listenaddress": []string{
			"[::]:22",
			"0.0.0.0:22",
		},
		"passwordauthentication": []string{
			"yes",
		},
		"permitrootlogin": []string{
			"without-password",
		},
		"port": []string{
			"22",
		},
		"pubkeyauthentication": []string{
			"yes",
		},
	}, steps, nil
}

func TestLocalSSH_EvaluatePolicies(t *testing.T) {

	logger := hclog.NewNullLogger()

	fetcher := NewTestSSHFetcher(logger, map[string]string{})

	localSSH := &LocalSSH{
		logger: logger,
	}

	observations, findings, err := localSSH.EvaluatePolicies(context.TODO(), fetcher, &proto.EvalRequest{
		PolicyPaths: []string{
			"examples/policies",
		},
	})

	if err != nil {
		t.Error(err)
	}

	if len(observations) <= 0 {
		t.Log("No observations returned from evaluation")
		t.Fail()
	}

	if len(findings) <= 0 {
		t.Log("No findings returned from evaluation")
		t.Fail()
	}
}
