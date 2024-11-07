package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/chris-cmsoft/concom/runner"
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

//func (l *LocalSSH) Namespace() (string, error) {
//	l.logger.Debug("Getting policy namespace")
//	return "local_ssh", nil
//}

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
		Level:      hclog.Trace,
		Output:     os.Stderr,
		JSONFormat: true,
	})

	localSSH := &LocalSSH{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	var pluginMap = map[string]goplugin.Plugin{
		"runner": &runner.RunnerPlugin{
			Impl: localSSH,
		},
	}

	logger.Debug("message from plugin", "foo", "bar")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins:         pluginMap,
	})
}

var handshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "BASIC_PLUGIN",
	MagicCookieValue: "hello",
}
