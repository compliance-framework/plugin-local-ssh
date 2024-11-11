package compliance_framework.local_ssh.require_public_key

test_ssh_password_off {
	count(violation) == 0 with input as {
        "pubkeyauthentication": [
            "yes"
        ]
    }
}

test_ssh_password_on {
	count(violation) == 1 with input as {
        "pubkeyauthentication": [
            "no"
        ]
    }
}
