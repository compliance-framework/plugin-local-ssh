package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	protolang "github.com/golang/protobuf/proto"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/timestamppb"
	"os"
	"os/exec"
	"time"

	"github.com/chris-cmsoft/conftojson/pkg"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/uuid"
	goplugin "github.com/hashicorp/go-plugin"
)

type LocalSSH struct {
	logger hclog.Logger
	data   map[string]interface{}
	config map[string]string
}

func (l *LocalSSH) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.Config
	return &proto.ConfigureResponse{}, nil
}

func (l *LocalSSH) PrepareForEval(req *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {
	ctx := context.TODO()
	l.logger.Debug("fetching local ssh configuration")
	cmd := exec.CommandContext(ctx, "ssh", "root@jgc", "sshd", "-T")
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

func (l *LocalSSH) Eval(request *proto.EvalRequest) (*proto.EvalResponse, error) {
	l.logger.Debug("evaluating local ssh against policies", "policy", request.BundlePath)
	ctx := context.TODO()

	startTime := time.Now()

	results, err := policyManager.New(ctx, l.logger, request.BundlePath).Execute(ctx, "local_ssh", l.data)
	if err != nil {
		l.logger.Error("Failed to create new policyManager object", "error", err)
		return &proto.EvalResponse{}, err
	}

	l.logger.Debug("local ssh evaluation completed", "results", results)

	response := runner.NewCallableEvalResponse()
	result := response.GetResult()

	hostname := os.Getenv("HOSTNAME")
	result.Title = fmt.Sprintf("SSH Configuration for host: %s", hostname)

	for _, result := range results {
		tasks := []*proto.Task{}
		for _, task := range result.Tasks {
			activities := []*proto.Activity{}

			for _, activity := range task.Activities {
				steps := []*proto.Step{}
				for _, step := range activity.Steps {
					steps = append(steps, &proto.Step{
						Title:     step.Title,
						SubjectId: "TODO",
					})
				}

				activities = append(activities, &proto.Activity{
					Title:       activity.Title,
					SubjectId:   "TODO",
					Description: activity.Description,
					Type:        activity.Type,
					Steps:       steps,
					Tools:       activity.Tools,
				})
			}

			tasks = append(tasks, &proto.Task{
				Title:       task.Title,
				Description: &task.Description,
				//Tasks: tasks,
				//Activities:  activities,
			})
		}

		if len(result.Violations) == 0 {
			title := fmt.Sprintf("Local SSH Validation on %s passed.", result.Policy.Package.PurePackage())
			response.AddObservation(&proto.Observation{
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
			response.AddFinding(&proto.Finding{
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
			response.AddObservation(observation)

			for _, violation := range result.Violations {
				status := runner.FindingTargetStatusNotSatisfied
				response.AddFinding(&proto.Finding{
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

			response.AddRiskEntry(&proto.Risk{
				Title:       risk.Title,
				Description: risk.Description,
				Statement:   risk.Statement,
				Props:       []*proto.Property{},
				Links:       []*proto.Link{},
			})
		}
	}

	endTime := time.Now()
	response.AddLogEntry(&proto.AssessmentLog_Entry{
		Title:       protolang.String("Local SSH check"),
		Description: protolang.String("Local SSH Plugin checks completed successfully"),
		Start:       timestamppb.New(startTime),
		End:         timestamppb.New(time.Now()),
	})

	result.Start = timestamppb.New(startTime)
	result.End = timestamppb.New(endTime)

	return response.Result(), err
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
