package compliance_framework.local_ssh.deny_password_auth

import future.keywords.in

title := "SSH password authentication is disabled"
description := "Checks whether SSH password authentication is disabled on the host machine."

violation[{
    "id": "ssh_password_auth",
}] if {
	"yes" in input.passwordauthentication
}
