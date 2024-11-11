package main

import (
	"fmt"
	policy_manager "github.com/chris-cmsoft/concom/policy-manager"
	"github.com/chris-cmsoft/concom/runner/proto"
	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/ast"
	"testing"
)

func TestLocalSSH_Eval(t *testing.T) {

	results := []policy_manager.Result{
		{
			Policy: struct {
				File        string
				Package     policy_manager.Package
				Annotations []*ast.Annotations
			}{
				File:        "something.rego",
				Package:     "compliance_framework.local_ssh.deny_password_auth",
				Annotations: []*ast.Annotations{},
			},
			Violations: []policy_manager.Violation{
				{
					"msg": "SSH Hosts are not allowed to have SSH password enabled",
				},
				{
					"msg": "Something else",
				},
			},
		},
	}
	// ==============================================

	results[0].Violations[0].GetString("title", "Local SSH Check failed.")

	observation_one := proto.Observation{
		Id:               uuid.New().String(),
		Title:            results[0].Violations[0].GetString("title", "Local SSH Check failed."),
		Description:      "",
		Props:            nil,
		Links:            nil,
		Remarks:          "",
		SubjectId:        "",
		Collected:        "",
		Expires:          "",
		RelevantEvidence: nil,
	}

	observation_two := proto.Observation{
		Id:               uuid.New().String(),
		Title:            "",
		Description:      "",
		Props:            nil,
		Links:            nil,
		Remarks:          "",
		SubjectId:        "",
		Collected:        "",
		Expires:          "",
		RelevantEvidence: nil,
	}

	finding := proto.Finding{
		Id:          uuid.New().String(),
		Title:       "",
		Description: "",
		Remarks:     "",
		Props:       nil,
		Links:       nil,
		SubjectId:   "",
		RelatedObservations: []string{
			observation_one.Id,
			observation_two.Id,
		},
		RelatedRisks: nil,
	}

	fmt.Println(finding)

}
