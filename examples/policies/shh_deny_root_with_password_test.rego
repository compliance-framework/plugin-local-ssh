package compliance_framework.local_ssh.deny_root_with_password

test_ssh_password_off {
	count(violation) == 0 with input as {
        "permitrootlogin": [
            "without-password"
        ]
    }
}

test_ssh_password_on {
	count(violation) == 1 with input as {
        "permitrootlogin": []
    }
}
