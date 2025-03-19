package compliance_framework.local_ssh.deny_root_with_password

import future.keywords.in

violation[{
    "title": "Root account should not be allowed to use password authentication",
    "description": "Root accounts using password is a severe security flaw, by which a brute force attack could gain elevated access to a host machine.",
    "remarks": "Remove password authentication from the root account, and use public keys or certificates as a stronger authentication method."
}] if {
	not "without-password" in input.permitrootlogin
}