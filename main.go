package main

import (
	"context"
	"errors"
	"github.com/chris-cmsoft/cf-plugin-local-ssh/internal"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"os"
	"slices"
)

type Config struct {
	Host       string
	Port       int32
	Connection struct {
		Url string
	}
	Hosts []string
}

type LocalSSH struct {
	logger hclog.Logger
	data   map[string]interface{}
	config *Config
}

func (l *LocalSSH) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = &Config{}
	err := req.Decode(l.config)
	if err != nil {
		return nil, err
	}
	l.logger.Info("Config", "host", l.config.Host, "port", l.config.Port)
	l.logger.Info("Config", "hosts", l.config.Hosts)
	l.logger.Info("Config", "connection", l.config.Connection.Url)
	return &proto.ConfigureResponse{}, nil
}

func (l *LocalSSH) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	fetcher := internal.NewLocalSSHFetcher(l.logger, map[string]string{})

	observations, findings, err := l.EvaluatePolicies(ctx, fetcher, req)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	if err = apiHelper.CreateObservations(ctx, observations); err != nil {
		l.logger.Error("Failed to send observations", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	if err = apiHelper.CreateFindings(ctx, findings); err != nil {
		l.logger.Error("Failed to send findings", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}
	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, err
}

func (l *LocalSSH) EvaluatePolicies(ctx context.Context, sshFetcher internal.SSHFetcher, req *proto.EvalRequest) ([]*proto.Observation, []*proto.Finding, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	findings := make([]*proto.Finding, 0)
	observations := make([]*proto.Observation, 0)

	l.logger.Debug("config", l.config)
	sshConfigMap, collectSteps, err := sshFetcher.FetchSSHConfiguration(ctx)
	activities = append(activities, &proto.Activity{
		Title:       "Collect SSH configuration",
		Description: "Collect SSH configuration from host machine, and prepare collected data for validation in policy engine",
		Steps:       collectSteps,
	})

	if err != nil {
		accumulatedErrors = errors.Join(accumulatedErrors, err)
		// We've failed to collect the needed information, we should exit.
		return observations, findings, accumulatedErrors
	}

	hostname := os.Getenv("HOSTNAME")
	subjects := []*proto.SubjectReference{
		{
			Type: "machine-instance",
			Attributes: map[string]string{
				"type":     "machine-instance",
				"hostname": hostname,
			},
			Title:   policyManager.Pointer("Machine Instance"),
			Remarks: policyManager.Pointer("A machine instance running the SSH software for remote access."),
			Props: []*proto.Property{
				{
					Name:    "hostname",
					Value:   hostname,
					Remarks: policyManager.Pointer("The local hostname of the machine where the plugin has been executed"),
				},
			},
		},
	}
	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  internal.StringAddressed("reference"),
					Text: internal.StringAddressed("The Continuous Compliance Framework"),
				},
			},
			Props: nil,
		},
		{
			Title: "Continuous Compliance Framework - Local SSH Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-local-ssh",
					Rel:  internal.StringAddressed("reference"),
					Text: internal.StringAddressed("The Continuous Compliance Framework' Local SSH Plugin"),
				},
			},
			Props: nil,
		},
	}
	components := []*proto.ComponentReference{
		{
			Identifier: "common-components/ssh",
		},
	}

	for _, policyPath := range req.GetPolicyPaths() {
		// Explicitly reset steps to make things readable
		processor := policyManager.NewPolicyProcessor(
			l.logger,
			map[string]string{
				"type":         "machine-instance",
				"hostname":     hostname,
				"_policy_path": policyPath,
			},
			subjects,
			components,
			actors,
			activities,
		)
		obs, finds, err := processor.GenerateResults(ctx, policyPath, sshConfigMap)
		observations = slices.Concat(observations, obs)
		findings = slices.Concat(findings, finds)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	l.logger.Info("collected observations", "count", len(observations))
	l.logger.Info("collected findings", "count", len(findings))

	return observations, findings, accumulatedErrors
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	localSSH := &LocalSSH{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("initiating local-ssh plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: localSSH,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
