package admission

import (
	"github.com/awslabs/cedar-access-control-for-k8s/internal/schema"
	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/ast"
	cedartypes "github.com/cedar-policy/cedar-go/types"
)

func AllowAllAdmissionPolicy() *cedar.Policy {
	return cedar.NewPolicyFromAST(
		ast.Permit().ActionInSet(
			cedartypes.EntityUID{Type: schema.AdmissionActionEntityType, ID: schema.AdmissionCreateAction},
			cedartypes.EntityUID{Type: schema.AdmissionActionEntityType, ID: schema.AdmissionUpdateAction},
			cedartypes.EntityUID{Type: schema.AdmissionActionEntityType, ID: schema.AdmissionDeleteAction},
			cedartypes.EntityUID{Type: schema.AdmissionActionEntityType, ID: schema.AdmissionDeleteAction},
		),
	)
}
