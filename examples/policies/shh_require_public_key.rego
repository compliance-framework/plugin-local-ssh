package compliance_framework.local_ssh.require_public_key

import future.keywords.in

violation[{
    "title": "Public key authentication is not enabled",
    "description": "Public key authentication should be used for strong and secure authentication on host machines.",
    "remarks": "Enabled public key authentication for host machine."
}] if {
	not "yes" in input.pubkeyauthentication
}
