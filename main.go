package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/chris-cmsoft/cf-plugin-local-ssh/internal"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"os"
	"slices"
)

type LocalSSH struct {
	logger hclog.Logger
	data   map[string]interface{}
	config map[string]string
}

func (l *LocalSSH) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *LocalSSH) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	fetcher := internal.NewLocalSSHFetcher(l.logger, l.config)

	evidences, err := l.EvaluatePolicies(ctx, fetcher, req)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	if err = apiHelper.CreateEvidence(ctx, evidences); err != nil {
		l.logger.Error("Failed to send evidence", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, err
}

func (l *LocalSSH) EvaluatePolicies(ctx context.Context, sshFetcher internal.SSHFetcher, req *proto.EvalRequest) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	evidences := make([]*proto.Evidence, 0)

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
		return evidences, accumulatedErrors
	}

	hostname := os.Getenv("HOSTNAME")
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
		},
	}
	components := []*proto.Component{
		{
			Identifier:  "common-components/ssh",
			Type:        "software",
			Title:       "OpenSSH Server",
			Description: "The OpenSSH server component provides encrypted remote login and command execution capabilities. This component enforces access controls, logging, and secure key management.",
			Purpose:     "Secure remote shell access and file transfer for managed systems.",
			Protocols: []*proto.Protocol{
				{
					UUID:  "70968CE7-AAF3-4E86-A4AF-6F68FCD42FF6",
					Name:  "SSH",
					Title: "Secure Shell",
					PortRanges: []*proto.PortRange{
						{
							End:       22,
							Start:     22,
							Transport: "TCP",
						},
					},
				},
			},
		},
	}
	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("machine-instance/%s", hostname),
			Type:       "web-server",
			Title:      fmt.Sprintf("Machine Instance %s", hostname),
			Props: []*proto.Property{
				{
					Name:    "hostname",
					Value:   hostname,
					Remarks: policyManager.Pointer("The local hostname of the machine where the plugin has been executed"),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: "common-components/ssh",
				},
			},
		},
	}
	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/ssh",
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("machine-instance/%s", hostname),
		},
	}

	for _, policyPath := range req.GetPolicyPaths() {
		processor := policyManager.NewPolicyProcessor(
			l.logger,
			map[string]string{
				"type":         "ssh",
				"hostname":     hostname,
				"_policy_path": policyPath,
			},
			subjects,
			components,
			inventory,
			actors,
			activities,
		)
		evidence, err := processor.GenerateResults(ctx, policyPath, sshConfigMap)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	l.logger.Debug("Successfully generated evidence", "count", len(evidences))

	return evidences, accumulatedErrors
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
