# Compliance Framework Local SSH Plugin

Fetches the local SSH configuration on a host using `sshd -T`, and runs passed policies against the output.

This plugin is intended to be run as part of an agent on a single host machine, 
where SSH configuration needs to be validated.

## Policies

When writing OPA / Rego policies for this plugin, they must be added under the `compliance_framework.local_ssh`
rego module:

```rego
# deny_password_auth.rego
# package compliance_framework.local_ssh.[YOUR_RULE_PATH]
package compliance_framework.local_ssh.deny_password_auth
```

The plugin expects Rego policies to output a `violation` key to indicate failed resources, which will be reported to the 
compliance framework. Additional data can be added to violations, that describe what failed, and recommendations on how 
to fix them.

Here is an example rego policy which ensures that passwords are turned off for SSH-able hosts.

```rego
# deny_password_auth.rego
package compliance_framework.local_ssh.deny_password_auth

import future.keywords.in

violation[{
    # Title describes the violation
    "title": "Host SSH is using password authentication.",
    # Description adds more details about the violation
    "description": "Host SSH should not use password, as this is insecure to brute force attacks from external sources.",
    # Remarks indicate how this can be fixed or remediated
    "remarks": "Migrate to using SSH Public Keys, and switch off password authentication."
}] {
	"yes" in input.passwordauthentication
}
```

## Releases

This plugin is released using goreleaser, which will ensure a binary is built for most OS and Architecture combinations. 

You can find the binaries on each release of this plugin in the GitHub releases page. 

[Not Yet Implemented] To run this plugin with the Compliance Agent, you can specify the release. 
The agent will take care of pulling the correct binary. 

```shell
concom agent --plugin=https://github.com/chris-cmsoft/concom-plugin-local-ssh/releases/tag/0.0.1
```
