package internal

import (
	"bufio"
	"bytes"
	"context"
	"github.com/chris-cmsoft/conftojson/pkg"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"os/exec"
)

type SSHFetcher interface {
	FetchSSHConfiguration(ctx context.Context) (map[string]interface{}, []*proto.Step, error)
}

type LocalSSHFetcher struct {
	logger hclog.Logger
	config map[string]string
}

func NewLocalSSHFetcher(logger hclog.Logger, config map[string]string) *LocalSSHFetcher {
	return &LocalSSHFetcher{
		logger: logger,
		config: config,
	}
}

func (l *LocalSSHFetcher) FetchSSHConfiguration(ctx context.Context) (map[string]interface{}, []*proto.Step, error) {
	steps := make([]*proto.Step, 0)
	var cmd *exec.Cmd
	l.logger.Debug("fetching local ssh configuration")
	if l.config["sudo"] == "true" || l.config["sudo"] == "1" {
		steps = append(steps, &proto.Step{
			Title:       "Fetch SSH configuration from host machine using sudo",
			Description: "Fetch SSH configuration from host machine, using `sshd -T` command. This will output the final configuration values used by the SSH service on the host machine.",
			Remarks:     StringAddressed("`sshd -T` is used to collect SSH information in aggregate, from all configurations files known by the SSH software package. Sudo is used to elevate privileges for the collection of configuration."),
		})
		cmd = exec.CommandContext(ctx, "sudo", "sshd", "-T")
	} else {
		steps = append(steps, &proto.Step{
			Title:       "Fetch SSH configuration from host machine",
			Description: "Fetch SSH configuration from host machine, using `sshd -T` command. This will output the final configuration values used by the SSH service on the host machine.",
			Remarks:     StringAddressed("`sshd -T` is used to collect SSH information in aggregate, from all configurations files known by the SSH software package."),
		})
		cmd = exec.CommandContext(ctx, "sshd", "-T")
	}
	stdout, err := cmd.Output()
	if err != nil {
		l.logger.Error("Failed to fetch SSH configuration (sshd -T)", "error", err)
		return nil, steps, err
	}

	l.logger.Debug("converting ssh configuration to json map for evaluation")
	steps = append(steps, &proto.Step{
		Title:       "Convert collected SSH configuration to JSON format",
		Description: "Convert SSH configuration collected by plugin to JSON format. This makes the configuration accessible for policy engines to validate and assert policy controls.",
	})
	sshConfigMap, err := l.convertToJson(stdout)
	if err != nil {
		l.logger.Error("Failed to convert SSH config to map", "error", err)
		return nil, steps, err
	}
	return sshConfigMap, steps, nil
}

func (l *LocalSSHFetcher) convertToJson(sshConfig []byte) (map[string]interface{}, error) {
	l.logger.Debug("converting ssh configuration to json map for evaluation")
	buf := bytes.NewBuffer(sshConfig)
	scanner := bufio.NewScanner(buf)
	sshConfigMap, err := pkg.ConvertConfToMap(scanner)
	if err != nil {
		l.logger.Error("Failed to convert SSH config to map", "error", err)
		return nil, err
	}
	return sshConfigMap, nil
}
