package main

import (
	"bufio"
	"bytes"
	"context"
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

//func (l *LocalSSH) Evaluate(query rego.PreparedEvalQuery) (rego.ResultSet, error) {
//	ctx := context.TODO()
//	result, err := query.Eval(ctx, rego.EvalInput(l.data))
//	return result, err
//}

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
			"runner": &runner.RunnerPlugin{
				Impl: localSSH,
			},
		},
	})
}
