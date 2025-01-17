package main

import (
	"github.com/chris-cmsoft/cf-plugin-local-ssh/internal"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	localSSH := internal.NewLocalSSH(logger)

	_, err := localSSH.Configure(&proto.ConfigureRequest{})
	if err != nil {
		logger.Error("Failed to configure plugin", "error", err)
	}

	_, err = localSSH.PrepareForEval(&proto.PrepareForEvalRequest{})
	if err != nil {
		logger.Error("Failed to prepare for eval", "error", err)
	}
}
