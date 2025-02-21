package main

import (
	policy_manager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner/proto"
	protolang "github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/ast"
	"google.golang.org/protobuf/types/known/timestamppb"
	"testing"
	"time"
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
			EvalOutput: &policy_manager.EvalOutput{
				Violations: []policy_manager.Violation{
					{
						Title: "SSH Hosts are not allowed to have SSH password enabled",
					},
					{
						Title: "Something else",
					},
				},
			},
		},
	}
	// ==============================================

	observation_one := proto.Observation{
		Uuid:        uuid.New().String(),
		Title:       protolang.String(results[0].Violations[0].Title),
		Description: "",
		Props:       nil,
		Links:       nil,
		Remarks:     protolang.String(""),
		Collected:   timestamppb.New(time.Now()),
		Expires:     timestamppb.New(time.Now().Add(time.Hour * 24)),
	}

	observation_two := proto.Observation{
		Uuid:             uuid.New().String(),
		Title:            protolang.String(""),
		Description:      "",
		Props:            nil,
		Links:            nil,
		Remarks:          protolang.String(""),
		Collected:        timestamppb.New(time.Now()),
		Expires:          timestamppb.New(time.Now().Add(time.Hour * 24)),
		RelevantEvidence: nil,
	}

	_ = proto.Finding{
		Title:       "",
		Description: "",
		Remarks:     protolang.String(""),
		Props:       nil,
		Links:       nil,
		RelatedObservations: []*proto.RelatedObservation{
			{
				ObservationUuid: observation_one.Uuid,
			},
			{
				ObservationUuid: observation_two.Uuid,
			},
		},
		RelatedRisks: nil,
	}
}
