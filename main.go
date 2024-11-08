package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/chris-cmsoft/concom/bundle"
	"github.com/chris-cmsoft/concom/runner"
	"github.com/chris-cmsoft/concom/runner/proto"
	"github.com/chris-cmsoft/conftojson/pkg"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"os/exec"
)

type LocalSSH struct {
	logger hclog.Logger
	data   map[string]interface{}
}

func (l *LocalSSH) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.logger.Debug("configuring local ssh plugin")
	l.logger.Debug("config passed", req.Config)
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

	evaluator := bundle.New(ctx, request.BundlePath)

	query, err := evaluator.BuildQuery(ctx, "local_ssh")
	if err != nil {
		return &proto.EvalResponse{}, err
	}

	l.logger.Debug("evaluating local ssh against policies", "query", query)
	//l.logger.Debug("evaluating local ssh against policies", "policy", l.data)

	results, err := evaluator.Execute(ctx, l.data)
	if err != nil {
		return &proto.EvalResponse{}, err
	}

	for _, result := range results {
		// Create Finding
		if len(result.Violations) > 0 {
			// We have some violations for the policies.
			// Let's check them
			fmt.Println("Package:", result.Policy.Package)
			fmt.Println("Additional Variables:", result.AdditionalVariables)
			fmt.Println("Violations:", result.Violations)
		}
	}

	l.logger.Debug("evaluation result", "result", results, "err", err)
	return &proto.EvalResponse{
		Status: 0,
		Observations: []*proto.Observation{
			{
				Id:               "12345",
				Title:            "Some Title",
				Description:      "Some Description",
				Props:            nil,
				Links:            nil,
				Remarks:          "Some Remark",
				SubjectId:        "123",
				Collected:        "123",
				Expires:          "123",
				RelevantEvidence: nil,
			},
		},
		Findings: []*proto.Finding{},
		Risks:    []*proto.Risk{},
		Logs:     []*proto.LogEntry{},
	}, err
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
