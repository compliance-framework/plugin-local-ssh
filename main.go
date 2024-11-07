package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	concomplugin "github.com/chris-cmsoft/concom/plugin"
	"github.com/chris-cmsoft/conftojson/pkg"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"os"
	"os/exec"
)

type LocalSSH struct {
	logger hclog.Logger
	data   map[string]interface{}
}

func (l *LocalSSH) PolicyNamespace() string {
	return "local_ssh"
}

func (l *LocalSSH) PrepareForEval() error {
	l.logger.Debug("Preparing to check SSH configuration")
	ctx := context.TODO()
	l.logger.Debug("Preparing to check SSH configuration")
	fmt.Println("Prep work being done")
	cmd := exec.CommandContext(ctx, "ssh", "root@jgc", "sshd", "-T")
	stdout, err := cmd.Output()
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(stdout)
	scanner := bufio.NewScanner(buf)

	sshConfigMap, err := pkg.ConvertConfToMap(scanner)
	if err != nil {
		return err
	}

	l.data = sshConfigMap
	l.logger.Debug("Done checking SSH configuration")
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
		Output:     os.Stderr,
		JSONFormat: true,
	})

	localSshPlugin := &LocalSSH{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	var pluginMap = map[string]goplugin.Plugin{
		"evaluator": &concomplugin.EvaluatorPlugin{Impl: localSshPlugin},
	}

	logger.Debug("message from plugin", "foo", "bar")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: concomplugin.HandshakeConfig,
		Plugins:         pluginMap,
	})
}
