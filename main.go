package main

import (
	"github.com/chris-cmsoft/cf-plugin-local-ssh/internal"
	"github.com/compliance-framework/agent/runner"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: internal.NewLocalSSH(logger),
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
