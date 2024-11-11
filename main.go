package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	policyManager "github.com/chris-cmsoft/concom/policy-manager"
	"github.com/chris-cmsoft/concom/runner"
	"github.com/chris-cmsoft/concom/runner/proto"
	"github.com/chris-cmsoft/conftojson/pkg"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"os/exec"
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
		return &proto.PrepareForEvalResponse{}, err
	}

	buf := bytes.NewBuffer(stdout)
	scanner := bufio.NewScanner(buf)

	l.logger.Debug("converting ssh configuration to json map for evaluation")
	sshConfigMap, err := pkg.ConvertConfToMap(scanner)
	if err != nil {
		return &proto.PrepareForEvalResponse{}, err
	}

	l.data = sshConfigMap
	l.logger.Debug("ssh configuration prepared for evaluation")
	return &proto.PrepareForEvalResponse{}, nil
}

func (l *LocalSSH) Eval(request *proto.EvalRequest) (*proto.EvalResponse, error) {
	l.logger.Debug("evaluating local ssh against policies", "policy", request.BundlePath)
	ctx := context.TODO()

	// policy path = directory
	// bundle = tar.gz
	// nothing = plugin itself is doing valuation

	results, err := policyManager.New(ctx, l.logger, request.BundlePath).Execute(ctx, "local_ssh", l.data)
	if err != nil {
		return &proto.EvalResponse{}, err
	}

	response := runner.NewCallableEvalResponse()

	for _, result := range results {
		// Create Finding
		if len(result.Violations) == 0 {
			response.AddFinding(&proto.Finding{
				Id:                  uuid.New().String(),
				Title:               "",
				Description:         "",
				Remarks:             "",
				Props:               nil,
				Links:               nil,
				SubjectId:           "",
				RelatedObservations: nil,
				RelatedRisks:        nil,
			})
		}

		if len(result.Violations) > 0 {

			response.AddObservation(&proto.Observation{
				Id:               uuid.New().String(),
				Title:            "",
				Description:      "",
				Props:            nil,
				Links:            nil,
				Remarks:          "",
				SubjectId:        "",
				Collected:        "",
				Expires:          "",
				RelevantEvidence: nil,
			})

			// We have some violations for the policies.
			// Let's check them
			fmt.Println("Package:", result.Policy.Package)
			fmt.Println("Additional Variables:", result.AdditionalVariables)
			fmt.Println("Violations:", result.Violations)
		}
	}

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
