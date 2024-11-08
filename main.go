package main

import (
	"bufio"
	"bytes"
	"context"
	"github.com/chris-cmsoft/concom/bundle"
	"github.com/chris-cmsoft/concom/runner"
	"github.com/chris-cmsoft/conftojson/pkg"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"os/exec"
)

type LocalSSH struct {
	logger hclog.Logger
	data   map[string]interface{}
}

func (l *LocalSSH) Configure(config map[string]string) error {
	l.logger.Debug("configuring local ssh plugin")
	l.logger.Debug("config passed", config)
	return nil
}

func (l *LocalSSH) PrepareForEval() error {
	ctx := context.TODO()
	l.logger.Debug("fetching local ssh configuration")
	cmd := exec.CommandContext(ctx, "ssh", "root@jgc", "sshd", "-T")
	stdout, err := cmd.Output()
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(stdout)
	scanner := bufio.NewScanner(buf)

	l.logger.Debug("converting ssh configuration to json map for evaluation")
	sshConfigMap, err := pkg.ConvertConfToMap(scanner)
	if err != nil {
		return err
	}

	l.data = sshConfigMap
	l.logger.Debug("ssh configuration prepared for evaluation")
	return nil
}

func (l *LocalSSH) Eval(bundlePath string) error {
	l.logger.Debug("evaluating local ssh against policies", "policy", bundlePath)
	ctx := context.TODO()

	evaluator := bundle.New(ctx, bundlePath)

	query, err := evaluator.BuildQuery(ctx, "local_ssh")
	if err != nil {
		return err
	}

	l.logger.Debug("evaluating local ssh against policies", "query", query)
	//l.logger.Debug("evaluating local ssh against policies", "policy", l.data)

	results, err := evaluator.Execute(ctx, l.data)

	for _, result := range results {
		// Create Finding
		if len(result.Violations) > 0 {

		}
	}

	l.logger.Debug("evaluation result", "result", results, "err", err)
	return err
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
