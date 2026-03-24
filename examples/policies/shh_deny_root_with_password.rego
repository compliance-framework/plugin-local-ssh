package compliance_framework.local_ssh.deny_root_with_password

import future.keywords.in

title := "Root SSH password authentication is disabled"
description := "Checks whether the root account is prevented from using password-based SSH authentication."

violation[{
    "id": "ssh_root_password_auth",
}] if {
	not "without-password" in input.permitrootlogin
}
