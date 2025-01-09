package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/chris-cmsoft/conftojson/pkg"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"os"
	"os/exec"
	"time"
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

	response := runner.NewCallableEvalResponse()

	hostname := os.Getenv("HOSTNAME")
	response.Title = fmt.Sprintf("SSH Configuration for host: %s", hostname)

	for _, result := range results {
		// Create Finding
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
				response.AddFinding(&proto.Finding{
					Id:          uuid.New().String(),
					Title:       violation.GetString("title", fmt.Sprintf("Validation on %s failed with violation %v", result.Policy.Package.PurePackage(), violation)),
					Description: violation.GetString("description", ""),

					Remarks:             violation.GetString("remarks", ""),
					RelatedObservations: []string{observation.Id},
				})
			}

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
