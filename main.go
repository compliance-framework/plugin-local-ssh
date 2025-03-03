package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/compliance-framework/configuration-service/sdk"
	"os"
	"os/exec"
	"time"

	"github.com/chris-cmsoft/conftojson/pkg"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	protolang "github.com/golang/protobuf/proto"
	"github.com/google/uuid"
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

func (l *LocalSSH) PrepareForEval(req *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {
	ctx := context.TODO()
	l.logger.Debug("fetching local ssh configuration")
	var cmd *exec.Cmd
	l.logger.Debug("config", l.config)
	if l.config["sudo"] == "true" || l.config["sudo"] == "1" {
		cmd = exec.CommandContext(ctx, "sudo", "sshd", "-T")
	} else {
		cmd = exec.CommandContext(ctx, "sshd", "-T")
	}
	stdout, err := cmd.Output()
	if err != nil {
		l.logger.Error("Failed to fetch SSH configuration (sshd -T)", "error", err)
		return &proto.PrepareForEvalResponse{}, err
	}

	buf := bytes.NewBuffer(stdout)
	scanner := bufio.NewScanner(buf)

	l.logger.Debug("converting ssh configuration to json map for evaluation")
	sshConfigMap, err := pkg.ConvertConfToMap(scanner)
	if err != nil {
		l.logger.Error("Failed to convert SSH config to map", "error", err)
		return &proto.PrepareForEvalResponse{}, err
	}

	l.data = sshConfigMap
	l.logger.Debug("ssh configuration prepared for evaluation")
	return &proto.PrepareForEvalResponse{}, nil
}

func (l *LocalSSH) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	l.logger.Debug("evaluating local ssh against policies", "policy", req.GetBundlePath())
	ctx := context.TODO()

	startTime := time.Now()

	results, err := policyManager.New(ctx, l.logger, req.GetBundlePath()).Execute(ctx, "local_ssh", l.data)
	if err != nil {
		l.logger.Error("Failed to evaluate against policy bundle", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	l.logger.Debug("local ssh evaluation completed", "results", results)

	hostname := os.Getenv("HOSTNAME")

	assessmentResult := runner.NewCallableAssessmentResult()
	assessmentResult.Title = fmt.Sprintf("SSH Configuration for host: %s", hostname)

	for _, result := range results {
		// TODO: Figure out how to send back tasks again
		// tasks := []*proto.Task{}
		// for _, task := range result.Tasks {
		// 	activities := []*proto.Activity{}

		// 	for _, activity := range task.Activities {
		// 		steps := []*proto.Step{}
		// 		for _, step := range activity.Steps {
		// 			steps = append(steps, &proto.Step{
		// 				Title:     step.Title,
		// 				SubjectId: "TODO",
		// 			})
		// 		}

		// 		activities = append(activities, &proto.Activity{
		// 			Title:       activity.Title,
		// 			SubjectId:   "TODO",
		// 			Description: activity.Description,
		// 			Type:        activity.Type,
		// 			Steps:       steps,
		// 			Tools:       activity.Tools,
		// 		})
		// 	}

		// 	tasks = append(tasks, &proto.Task{
		// 		Title:       task.Title,
		// 		Description: &task.Description,
		// 		//Tasks: tasks,
		// 		//Activities:  activities,
		// 	})
		// }

		if len(result.Violations) == 0 {
			title := fmt.Sprintf("Local SSH Validation on %s passed.", result.Policy.Package.PurePackage())
			assessmentResult.AddObservation(&proto.Observation{
				Uuid:        uuid.New().String(),
				Title:       &title,
				Description: fmt.Sprintf("Observed no violations on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage()),
				Collected:   timestamppb.New(time.Now()),
				Expires:     timestamppb.New(time.Now().AddDate(0, 1, 0)), // Add one month for the expiration
				RelevantEvidence: []*proto.RelevantEvidence{
					{
						Description: fmt.Sprintf("Policy %v was executed against the Local SSH output from machine XXX, using the Local SSH Compliance Plugin", result.Policy.Package.PurePackage()),
					},
				},
			})

			status := runner.FindingTargetStatusSatisfied
			assessmentResult.AddFinding(&proto.Finding{
				Title:       fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage()),
				Description: fmt.Sprintf("No violations found on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage()),
				Target: &proto.FindingTarget{
					Status: &proto.ObjectiveStatus{
						State: status,
					},
				},
			})
		}

		if len(result.Violations) > 0 {
			title := fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage())
			observation := &proto.Observation{
				Uuid:        uuid.New().String(),
				Title:       &title,
				Description: fmt.Sprintf("Observed %d violation(s) on the %s policy within the Local SSH Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage()),
				Collected:   timestamppb.New(time.Now()),
				Expires:     timestamppb.New(time.Now().AddDate(0, 1, 0)), // Add one month for the expiration
				RelevantEvidence: []*proto.RelevantEvidence{
					{
						Description: fmt.Sprintf("Policy %v was executed against the Local SSH output from machine XXX, using the Local SSH Compliance Plugin", result.Policy.Package.PurePackage()),
					},
				},
			}
			assessmentResult.AddObservation(observation)

			for _, violation := range result.Violations {
				status := runner.FindingTargetStatusNotSatisfied
				assessmentResult.AddFinding(&proto.Finding{
					Title:       violation.Title,
					Description: violation.Description,
					Remarks:     &violation.Remarks,
					RelatedObservations: []*proto.RelatedObservation{
						{
							ObservationUuid: observation.Uuid,
						},
					},
					Target: &proto.FindingTarget{
						Status: &proto.ObjectiveStatus{
							State: status,
						},
					},
				})
			}
		}

		for _, risk := range result.Risks {
			links := []*proto.Link{}
			for _, link := range risk.Links {
				links = append(links, &proto.Link{
					Href: link.URL,
					Text: &link.Text,
				})
			}

			assessmentResult.AddRiskEntry(&proto.Risk{
				Title:       risk.Title,
				Description: risk.Description,
				Statement:   risk.Statement,
				Props:       []*proto.Property{},
				Links:       []*proto.Link{},
			})
		}
	}

	endTime := time.Now()

	assessmentResult.Start = timestamppb.New(startTime)
	assessmentResult.End = timestamppb.New(endTime)

	assessmentResult.AddLogEntry(&proto.AssessmentLog_Entry{
		Title:       protolang.String("Local SSH check"),
		Description: protolang.String("Local SSH Plugin checks completed successfully"),
		Start:       timestamppb.New(startTime),
		End:         timestamppb.New(endTime),
	})

	streamId, err := sdk.SeededUUID(map[string]string{
		"type":      "ssh",
		"_hostname": hostname,
		"_policy":   req.GetBundlePath(),
	})
	if err != nil {
		return nil, err
	}
	if err := apiHelper.CreateResult(streamId.String(), map[string]string{
		"type":      "ssh",
		"_hostname": hostname,
		"_policy":   req.GetBundlePath(),
	}, assessmentResult.Result()); err != nil {
		l.logger.Error("Failed to add assessment result", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
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
