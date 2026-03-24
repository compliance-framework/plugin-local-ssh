package compliance_framework.local_ssh.require_public_key

import future.keywords.in

title := "SSH public key authentication is enabled"
description := "Checks whether SSH public key authentication is enabled on the host machine."

violation[{
    "id": "ssh_require_public_key",
}] if {
	not "yes" in input.pubkeyauthentication
}
