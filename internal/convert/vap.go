package convert

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/schema"
	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/ast"
	cedartypes "github.com/cedar-policy/cedar-go/types"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/klog/v2"
)

func VapToCedar(vap *admissionv1.ValidatingAdmissionPolicy) (*cedar.PolicySet, error) {
	resp := cedar.NewPolicySet()

	for vi := range vap.Spec.Validations {

		if vap.Spec.MatchConstraints == nil {
			// skip match constraints for now
			continue
		}
		validationWhen, err := ParseCEL(vap.Spec.Validations[vi].Expression)
		if err != nil {
			klog.Errorf("failed to parse CEL expression %v in validation %d: %v", vap.Spec.Validations[vi].Expression, vi, err)
			continue
		}
		when := *validationWhen

		for ri, rr := range vap.Spec.MatchConstraints.ResourceRules {
			localPolicy := ast.Forbid().Annotate(
				cedartypes.Ident("ValidatingAdmissionPolicy"), cedartypes.String(vap.Name),
			).Annotate(
				cedartypes.Ident("ResourceRule"), cedartypes.String(strconv.Itoa(ri)),
			).Annotate(
				cedartypes.Ident("Validation"), cedartypes.String(strconv.Itoa(vi)),
			)
			rrOps := []string{}
			for _, op := range rr.Operations {
				rrOps = append(rrOps, string(op))
			}
			rrOps = reduceIfHasStar(rrOps)
			slices.Sort(rrOps)
			lowercase(rrOps)
			// all actions are equiv to "*"
			if slices.Equal(rrOps, []string{"connect", "create", "delete", "update"}) {
				rrOps = []string{"*"}
			}
			switch len(rrOps) {
			case 0:
				// Invalid
				continue
			case 1:
				if rrOps[0] != "*" {
					localPolicy = localPolicy.ActionEq(cedartypes.EntityUID{
						Type: schema.AuthorizationActionEntityType,
						// TODO; match against known action IDs
						ID: cedartypes.String(strings.ToLower(rrOps[0])),
					})
				}
				// * means all operations, so no action specification is necessary
			default:
				actions := []cedartypes.EntityUID{}
				for _, verb := range rrOps {
					actions = append(actions, cedartypes.EntityUID{
						Type: schema.AdmissionActionEntityType,
						ID:   cedartypes.String(strings.ToLower(verb)),
					})
				}
				localPolicy = localPolicy.ActionInSet(actions...)
			}

			apiGroups := reduceIfHasStar(rr.APIGroups)
			slices.Sort(apiGroups)
			emptyApiToCore(apiGroups)
			if len(rr.APIGroups) == 0 {
				rr.APIGroups = []string{"*"}
			}

			apiVersions := reduceIfHasStar(rr.APIVersions)
			slices.Sort(apiVersions)
			if len(apiVersions) == 0 {
				apiVersions = []string{"*"}
			}

			resources := reduceIfHasStar(rr.Resources)
			slices.Sort(resources)
			if len(resources) == 0 {
				resources = []string{"*"}
			}
			// TODO look up API versions/Kind for
			if apiGroups[0] != "*" && apiVersions[0] != "*" && resources[0] != "*" {
				if len(apiGroups) == 1 && len(apiVersions) == 1 && len(resources) == 1 {

					parts := strings.Split(apiGroups[0], ".")
					slices.Reverse(parts)
					apiGroup := strings.Join(parts, "::")
					localPolicy = localPolicy.ResourceIs(cedartypes.EntityType(strings.Join([]string{
						apiGroup,
						apiVersions[0],
						cases.Title(language.AmericanEnglish).String(resources[0]),
					}, "::")))
					// single resource type
				} else {
					// TODO: ensure no `/` in resources
					resourceIsNodes := []ast.Node{}
					for _, apiGroup := range apiGroups {
						parts := strings.Split(apiGroup, ".")
						slices.Reverse(parts)
						apiGroup = strings.Join(parts, "::")
						for _, apiVersion := range apiVersions {
							for _, resource := range resources {
								// TODO: look up  Kind (`cronjobs` != `Cronjobs`, its `CronJobs`)
								rt := strings.Join([]string{
									apiGroup,
									apiVersion,
									cases.Title(language.AmericanEnglish).String(resource)}, "::")
								resourceIsNodes = append(resourceIsNodes,
									ast.Resource().Is(cedartypes.EntityType(rt)),
								)
							}
						}
					}
					if when == emptyNode {
						when = resourceIsNodes[0]
					} else {
						when = when.And(resourceIsNodes[0])
					}
					if len(resourceIsNodes) > 1 {
						for _, resourceIsNode := range resourceIsNodes[1:] {
							when = when.Or(resourceIsNode)
						}
					}
				}
			} else if apiGroups[0] == "*" && apiVersions[0] == "*" && resources[0] == "*" {
				// all resource types
			} else {
				// We can't wildcard over cedar namespaces, and we won't write a rule that applies to the wrong types
				// So we'll log it and alert the user
				klog.InfoS("Cannot construct a validation over a wildcard of one of apiGroups, apiVersions, or resources",
					"apiGroups", rr.APIGroups,
					"apiVersions", rr.APIVersions,
					"resources", rr.Resources,
					"vap", vap.Name,
					"validationIndex", vi,
					"matchConstraints.ResourceRules", ri,
				)
				goto nextValidation
			}
			var nameWhen ast.Node
			switch len(rr.ResourceNames) {
			case 0:
				// no-op
			case 1:
				nameWhen = ast.Resource().Has("meta").And(
					ast.Resource().Access("meta").Has("name").And(
						ast.Resource().Access("meta").Access("name").Equal(ast.String(rr.ResourceNames[0])),
					),
				)
			default:
				resourceNames := []ast.Node{}
				for _, resourceName := range rr.ResourceNames {
					resourceNames = append(resourceNames, ast.String(resourceName))
				}
				nameWhen = ast.Resource().Has("meta").And(
					ast.Resource().Access("meta").Has("name").And(
						ast.Set(resourceNames...).Contains(ast.Resource().Access("meta").Access("name")),
					),
				)
			}

			if nameWhen != emptyNode {
				if when == emptyNode {
					when = nameWhen
				} else {
					when = when.And(nameWhen)
				}
			}

			if when != emptyNode {
				localPolicy = localPolicy.When(when)
			}
			name := fmt.Sprintf("%s.%d.%d", vap.Name, vi, ri)
			resp.Store(cedartypes.PolicyID(name), cedar.NewPolicyFromAST(localPolicy))
		}

	nextValidation:
	}

	return resp, nil
}

func emptyApiToCore(apiGroups []string) {
	for i, apiGroup := range apiGroups {
		if apiGroup == "" {
			apiGroups[i] = "core"
		}
	}
}

func lowercase(sl []string) {
	for i, s := range sl {
		sl[i] = strings.ToLower(s)
	}
}
