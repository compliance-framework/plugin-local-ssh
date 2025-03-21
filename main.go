package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/chris-cmsoft/cf-plugin-local-ssh/internal"
	"github.com/google/uuid"
	"os"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	startTime := time.Now()
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

	for _, policyPath := range req.GetPolicyPaths() {
		// Explicitly reset steps to make things readable
		steps := make([]*proto.Step, 0)
		steps = append(steps, &proto.Step{
			Title:       "Compile policy bundle",
			Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
		})
		steps = append(steps, &proto.Step{
			Title:       "Execute policy bundle",
			Description: "Using previously collected JSON-formatted SSH configuration, execute the compiled policies",
		})
		results, err := policyManager.New(ctx, l.logger, policyPath).Execute(ctx, "local_ssh", sshConfigMap)
		if err != nil {
			l.logger.Error("Failed to evaluate against policy bundle", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			return observations, findings, accumulatedErrors
		}

		activities = append(activities, &proto.Activity{
			Title:       "Execute policy",
			Description: "Prepare and compile policy bundles, and execute them using the prepared SSH configuration data",
			Steps:       steps,
		})

		l.logger.Debug("local ssh evaluation completed", "results", results)
		hostname := os.Getenv("HOSTNAME")
		subjectAttributeMap := map[string]string{
			"type":     "machine-instance",
			"hostname": hostname,
		}
		subjects := []*proto.SubjectReference{
			{
				Type:       "machine-instance",
				Attributes: subjectAttributeMap,
				Title:      internal.StringAddressed("Machine Instance"),
				Remarks:    internal.StringAddressed("A machine instance running the SSH software for remote access."),
				Props: []*proto.Property{
					{
						Name:    "hostname",
						Value:   hostname,
						Remarks: internal.StringAddressed("The local hostname of the machine where the plugin has been executed"),
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

		activities = append(activities, &proto.Activity{
			Title:       "Compile Results",
			Description: "Using the output from policy execution, compile the resulting output to Observations and Findings, marking any violations, risks, and other OSCAL-familiar data",
			Steps:       steps,
		})
		for _, result := range results {
			// Observation UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
			// This acts as an identifier to show the history of an observation.
			observationUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
				"type":        "observation",
				"policy":      result.Policy.Package.PurePackage(),
				"policy_file": result.Policy.File,
				"policy_path": policyPath,
			})
			observationUUID, err := sdk.SeededUUID(observationUUIDMap)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				// We've been unable to do much here, but let's try the next one regardless.
				continue
			}

			// Finding UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
			// This acts as an identifier to show the history of a finding.
			findingUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
				"type":        "finding",
				"policy":      result.Policy.Package.PurePackage(),
				"policy_file": result.Policy.File,
				"policy_path": policyPath,
			})
			findingUUID, err := sdk.SeededUUID(findingUUIDMap)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				// We've been unable to do much here, but let's try the next one regardless.
				continue
			}

			observation := proto.Observation{
				ID:         uuid.New().String(),
				UUID:       observationUUID.String(),
				Collected:  timestamppb.New(startTime),
				Expires:    timestamppb.New(startTime.Add(24 * time.Hour)),
				Origins:    []*proto.Origin{{Actors: actors}},
				Subjects:   subjects,
				Activities: activities,
				Components: components,
				RelevantEvidence: []*proto.RelevantEvidence{
					{
						Description: fmt.Sprintf("Policy %v was executed against the Local SSH configuration, using the Local SSH Compliance Plugin", result.Policy.Package.PurePackage()),
					},
				},
			}

			newFinding := func() *proto.Finding {
				return &proto.Finding{
					ID:        uuid.New().String(),
					UUID:      findingUUID.String(),
					Collected: timestamppb.New(time.Now()),
					Labels: map[string]string{
						"type":         "ssh",
						"host":         hostname,
						"_policy":      result.Policy.Package.PurePackage(),
						"_policy_path": result.Policy.File,
					},
					Origins:             []*proto.Origin{{Actors: actors}},
					Subjects:            subjects,
					Components:          components,
					RelatedObservations: []*proto.RelatedObservation{{ObservationUUID: observation.ID}},
					Controls:            nil,
				}
			}

			if len(result.Violations) == 0 {
				observation.Title = internal.StringAddressed(fmt.Sprintf("Local SSH Validation on %s passed.", result.Policy.Package.PurePackage()))
				observation.Description = fmt.Sprintf("Observed no violations on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage())
				observations = append(observations, &observation)

				finding := newFinding()
				finding.Title = fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())
				finding.Description = fmt.Sprintf("No violations found on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage())
				finding.Status = &proto.FindingStatus{
					State: runner.FindingTargetStatusSatisfied,
				}
				findings = append(findings, finding)
				continue
			}

			if len(result.Violations) > 0 {
				observation.Title = internal.StringAddressed(fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage()))
				observation.Description = fmt.Sprintf("Observed %d violation(s) on the %s policy within the Local SSH Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage())
				observations = append(observations, &observation)

				for _, violation := range result.Violations {
					finding := newFinding()
					finding.Title = violation.Title
					finding.Description = violation.Description
					finding.Remarks = internal.StringAddressed(violation.Remarks)
					finding.Status = &proto.FindingStatus{
						State: runner.FindingTargetStatusNotSatisfied,
					}
					findings = append(findings, finding)
				}
			}
		}
	}
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
