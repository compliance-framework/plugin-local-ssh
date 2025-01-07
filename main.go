package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/chris-cmsoft/conftojson/pkg"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
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
	cmd := exec.CommandContext(ctx, "sshd", "-T")
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

	start_time := time.Now().Format(time.RFC3339)

	results, err := policyManager.New(ctx, l.logger, request.BundlePath).Execute(ctx, "local_ssh", l.data)
	if err != nil {
		l.logger.Error("Failed to create new policyManager object", "error", err)
		return &proto.EvalResponse{}, err
	}

	l.logger.Debug("local ssh evaluation completed", "results", results)

	response := runner.NewCallableEvalResponse()

	hostname := os.Getenv("HOSTNAME")
	response.Title = fmt.Sprintf("SSH Configuration for host: %s", hostname)

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
				Description: task.Description,
				Activities:  activities,
			})
		}

		if len(result.Violations) == 0 {
			response.AddObservation(&proto.Observation{
				Id:          uuid.New().String(),
				Title:       fmt.Sprintf("Local SSH Validation on %s passed.", result.Policy.Package.PurePackage()),
				Description: fmt.Sprintf("Observed no violations on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage()),
				Collected:   time.Now().Format(time.RFC3339),
				Expires:     time.Now().AddDate(0, 1, 0).Format(time.RFC3339), // Add one month for the expiration
				RelevantEvidence: []*proto.Evidence{
					{
						Description: fmt.Sprintf("Policy %v was executed against the Local SSH output from machine XXX, using the Local SSH Compliance Plugin", result.Policy.Package.PurePackage()),
					},
				},
			})

			status := proto.FindingStatus_MITIGATED
			statusString := proto.FindingStatus_name[int32(status)]
			response.AddFinding(&proto.Finding{
				Id:          uuid.New().String(),
				Title:       fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage()),
				Description: fmt.Sprintf("No violations found on the %s policy within the Local SSH Compliance Plugin.", result.Policy.Package.PurePackage()),

				Status: statusString,

				Tasks: tasks,
			})
		}

		if len(result.Violations) > 0 {
			observation := &proto.Observation{
				Id:          uuid.New().String(),
				Title:       fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage()),
				Description: fmt.Sprintf("Observed %d violation(s) on the %s policy within the Local SSH Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage()),
				Collected:   time.Now().Format(time.RFC3339),
				Expires:     time.Now().AddDate(0, 1, 0).Format(time.RFC3339), // Add one month for the expiration
				RelevantEvidence: []*proto.Evidence{
					{
						Description: fmt.Sprintf("Policy %v was executed against the Local SSH output from machine XXX, using the Local SSH Compliance Plugin", result.Policy.Package.PurePackage()),
					},
				},
			}
			response.AddObservation(observation)

			for _, violation := range result.Violations {
				status := proto.FindingStatus_OPEN
				statusString := proto.FindingStatus_name[int32(status)]
				response.AddFinding(&proto.Finding{
					Id:          uuid.New().String(),
					Title:       violation.Title,
					Description: violation.Description,

					Remarks:             violation.Remarks,
					RelatedObservations: []string{observation.Id},
					Status:              statusString,

					Tasks: tasks,
				})
			}
		}

		for _, risk := range result.Risks {
			links := []*proto.Link{}
			for _, link := range risk.Links {
				links = append(links, &proto.Link{
					Href:             link.URL,
					MediaType:        "TODO",
					Rel:              "TODO",
					ResourceFragment: "TODO",
					Text:             link.Text,
				})
			}

			response.AddRiskEntry(&proto.Risk{
				Title:       risk.Title,
				SubjectId:   "TODO",
				Description: risk.Description,
				Statement:   risk.Statement,
				Props:       []*proto.Property{},
				Links:       []*proto.Link{},
			})
		}
	}

	response.AddLogEntry(&proto.LogEntry{
		Title:       "Local SSH check",
		Description: "Local SSH Plugin checks completed successfully",
		Start:       start_time,
		End:         time.Now().Format(time.RFC3339),
	})

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
