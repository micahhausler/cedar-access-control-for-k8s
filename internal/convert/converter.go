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
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/klog/v2"
)

var emptyNode ast.Node

func ClusterRoleBindingToCedar(crb rbacv1.ClusterRoleBinding, clusterRole rbacv1.ClusterRole) *cedar.PolicySet {
	return rbacToCedar(NewClusterRoleBinder(crb), NewClusterRoleRuler(clusterRole), "")
}

func RoleBindingToCedar(rb rbacv1.RoleBinding, role rbacv1.Role) *cedar.PolicySet {
	return rbacToCedar(NewRoleBinder(rb), NewRoleRuler(role), role.Namespace)
}

func RoleBindingRulerToCedar(rb rbacv1.RoleBinding, ruler Ruler) *cedar.PolicySet {
	return rbacToCedar(NewRoleBinder(rb), ruler, rb.Namespace)
}

func rbacToCedar(binder Binder, ruler Ruler, namespace string) *cedar.PolicySet {
	resp := cedar.NewPolicySet()
	principals := []cedartypes.EntityUID{}

	for _, subject := range binder.Subjects() {
		switch subject.Kind {
		case "Group":
			principals = append(principals, cedartypes.EntityUID{
				Type: schema.GroupEntityType,
				ID:   cedartypes.String(subject.Name),
			})
		case "User":
			// TODO: don't reference user using name as ID, just compare the username
			principals = append(principals, cedartypes.EntityUID{
				Type: schema.UserEntityType,
				// We otherwise distinguish Users by UID, but its fine here since we
				// never refer to this principal by ID in the final policy
				ID: cedartypes.String(subject.Name),
			})
		case "ServiceAccount":
			// TODO: don't reference SA using name as ID, just compare the namespace and name
			principals = append(principals, cedartypes.EntityUID{
				Type: schema.ServiceAccountEntityType,
				ID:   cedartypes.String("system:serviceaccount:" + subject.Namespace + ":" + subject.Name),
			})
		}
	}
	for pi, principal := range principals {

		// TODO: Aggregation rules?
		for ri, rule := range ruler.Rules() {
			policy := ast.Permit().Annotate(
				cedartypes.Ident(binder.Type()), cedartypes.String(binder.Name()),
			).Annotate(
				cedartypes.Ident(ruler.Type()), cedartypes.String(ruler.Name()),
			).Annotate(
				"policyRule", cedartypes.String(fmt.Sprintf("%02d", ri)),
			)
			if namespace != "" {
				policy = policy.Annotate("namespace", cedartypes.String(namespace))
			}

			var when ast.Node

			switch principal.Type {
			case schema.GroupEntityType:
				policy = policy.PrincipalIn(principal)
			case schema.ServiceAccountEntityType:
				policy = policy.PrincipalIs(schema.ServiceAccountEntityType)
				parts := strings.Split(string(principal.ID), ":")
				if len(parts) != 4 {
					klog.ErrorS(fmt.Errorf("invalid service account ID"), "Didn't get 4 strings when splitting on colon. Skipping this rule", "name", principal.ID)
					continue
				}
				when = ast.Principal().Access("namespace").Equal(ast.String(parts[2])).And(
					ast.Principal().Access("name").Equal(ast.String(parts[3])),
				)
			case schema.UserEntityType:
				policy = policy.PrincipalIs(schema.UserEntityType)
				when = ast.Principal().Access("name").Equal(ast.String(principal.ID))
			}

			// if the policy has a "*" and other verbs, we can just use "*"
			rule.Verbs = reduceIfHasStar(rule.Verbs)

			switch len(rule.Verbs) {
			case 1:
				if rule.Verbs[0] != "*" {
					policy = policy.ActionEq(cedartypes.EntityUID{
						Type: schema.AuthorizationActionEntityType,
						ID:   cedartypes.String(rule.Verbs[0]),
					})
				}
				// * verb encompases all actions, so no policy specification required
			default:
				actions := []cedartypes.EntityUID{}
				for _, verb := range rule.Verbs {
					actions = append(actions, cedartypes.EntityUID{
						Type: schema.AuthorizationActionEntityType,
						ID:   cedartypes.String(verb),
					})
				}
				policy = policy.ActionInSet(actions...)
			}

			if len(rule.NonResourceURLs) > 0 {
				policy = policy.ResourceIs(schema.NonResourceURLEntityType)

				when = conditionForNonResourceURLs(rule)

				if when != emptyNode {
					policy = policy.When(when)
				}
				policyId := cedar.PolicyID(binder.Name() + strconv.Itoa(pi) + strconv.Itoa(ri))
				resp.Store(policyId, cedar.NewPolicyFromAST(policy))
			} else {
				rule.APIGroups = reduceIfHasStar(rule.APIGroups)
				rule.Resources = reduceIfHasStar(rule.Resources)
				// RBAC doesn't allow "*" as a resource name: empty slice means "*"

				condition := conditionForAPIGroups(rule)
				condition = conditionForResources(condition, rule)
				condition = conditionForResourceNames(condition, rule)

				if namespace != "" {
					condition = condition.And(ast.Resource().Has("namespace").And(
						ast.Resource().Access("namespace").Equal(ast.String(namespace))),
					)
				}

				if when != emptyNode {
					if condition != emptyNode {
						policy = policy.When(when.And(condition))
					} else {
						policy = policy.When(when)
					}
				} else if condition != emptyNode {
					policy = policy.When(condition)
				}

				// if no subresources
				if !hasSubResources(rule) {
					policy = policy.Unless(ast.Resource().Has("subresource"))
				}

				policy = policy.ResourceIs(schema.ResourceEntityType)
				policyId := cedar.PolicyID(binder.Name() + ":" + binder.Type() + ":" + strconv.Itoa(pi) + strconv.Itoa(ri))
				resp.Store(policyId, cedar.NewPolicyFromAST(policy))

			}
		}
		pi += 1
	}
	return resp
}

func reduceIfHasStar(slice []string) []string {
	if slices.Contains(slice, "*") {
		return []string{"*"}
	}
	return slice
}

func conditionForNonResourceURLs(rule rbacv1.PolicyRule) ast.Node {
	if len(rule.NonResourceURLs) == 1 {
		if rule.NonResourceURLs[0] == "*" {
			return emptyNode
		}
		if strings.HasSuffix(rule.NonResourceURLs[0], "*") {
			return ast.Resource().Has("path").And(
				ast.Resource().Access("path").Like(cedartypes.NewPattern(rule.NonResourceURLs[0])),
			)
		}
		return ast.Resource().Access("path").Equal(ast.String(rule.NonResourceURLs[0]))
	}

	wildCardUrls := []string{}
	nonWildCardUrls := []string{}
	for _, nonResourceURL := range rule.NonResourceURLs {
		if strings.HasSuffix(nonResourceURL, "*") {
			wildCardUrls = append(wildCardUrls, nonResourceURL)
		} else {
			nonWildCardUrls = append(nonWildCardUrls, nonResourceURL)
		}
	}

	condition := ast.Node{}

	if len(wildCardUrls) > 0 {
		if len(wildCardUrls) == 1 {
			condition = ast.Resource().Has("path").And(
				ast.Resource().Access("path").Like(cedartypes.NewPattern(wildCardUrls[0])),
			)
		} else {
			condition = ast.Resource().Has("path")
			localCondition := ast.Node{}
			for wi := range wildCardUrls {
				if wi == 0 {
					localCondition = ast.Resource().Access("path").Like(cedartypes.NewPattern(wildCardUrls[wi]))
					continue
				}
				localCondition = localCondition.Or(
					ast.Resource().Access("path").Like(cedartypes.NewPattern(wildCardUrls[wi])),
				)
			}
			condition = condition.And(localCondition)
		}
	}

	if len(nonWildCardUrls) > 0 {
		if len(nonWildCardUrls) == 1 {
			if condition != emptyNode {
				condition = condition.And(
					ast.Resource().Access("path").Equal(ast.String(nonWildCardUrls[0])),
				)
			} else {
				condition = ast.Resource().Access("path").Equal(ast.String(nonWildCardUrls[0]))
			}

		} else {
			nonWildCardUrlNodes := []ast.Node{}
			for _, nonWildCardUrl := range nonWildCardUrls {
				nonWildCardUrlNodes = append(nonWildCardUrlNodes, ast.String(nonWildCardUrl))
			}
			localCondition := ast.Set(nonWildCardUrlNodes...).Contains(ast.Resource().Access("path"))
			if condition != emptyNode {
				condition = condition.Or(localCondition)
			} else {
				condition = localCondition
			}
		}
	}

	return condition
}

func conditionForAPIGroups(rule rbacv1.PolicyRule) ast.Node {
	condition := ast.Resource().Access("apiGroup").Equal(ast.String(rule.APIGroups[0]))
	if len(rule.APIGroups) == 1 && rule.APIGroups[0] == "*" {
		return emptyNode
	}
	if len(rule.APIGroups) > 1 {
		apiGroups := []ast.Node{}
		for _, apiGroup := range rule.APIGroups {
			apiGroups = append(apiGroups, ast.String(apiGroup))
		}
		condition = ast.Set(apiGroups...).Contains(ast.Resource().Access("apiGroup"))

	}
	return condition
}

func hasSubResources(rule rbacv1.PolicyRule) bool {
	for _, resource := range rule.Resources {
		if strings.Contains(resource, "/") {
			return true
		}
	}
	return false
}

func conditionForResources(condition ast.Node, rule rbacv1.PolicyRule) (when ast.Node) {
	if len(rule.Resources) == 1 {
		if rule.Resources[0] == "*" {
			return condition
		}

		if !strings.Contains(rule.Resources[0], "/") {
			// handle single resource without subresource
			localCondition := ast.Resource().Access("resource").Equal(ast.String(rule.Resources[0]))
			if condition != emptyNode {
				condition = condition.And(ast.Resource().Access("resource").Equal(ast.String(rule.Resources[0])))
			} else {
				condition = localCondition
			}
		} else {
			// handle subresources
			left, right := strings.SplitN(rule.Resources[0], "/", 2)[0], strings.SplitN(rule.Resources[0], "/", 2)[1]

			// "*" means all .resources unconditionally, so no condition needed
			if left != "*" {
				localCondition := ast.Resource().Access("resource").Equal(ast.String(left))
				if condition != emptyNode {
					condition = condition.And(localCondition)
				} else {
					condition = localCondition
				}
			}

			if right == "*" {
				// TODO: Do we need the `resource.subresource != ""` check? Or does presence mean non-empty
				localCondition := ast.Resource().Has("subresource").And(ast.Resource().Access("subresource").NotEqual(ast.String("")))
				// has subresource and subresource is not empty
				if condition != emptyNode {
					condition = condition.And(localCondition)
				} else {
					condition = localCondition
				}
			} else {
				localCondition := ast.Resource().Has("subresource").And(
					ast.Resource().Access("subresource").Equal(ast.String(right)),
				)
				if condition != emptyNode {
					condition = condition.And(localCondition)
				} else {
					condition = localCondition
				}
			}
		}
	} else {
		// split subresource entries from regular resources
		subResourceEntries := []string{}
		regularEntries := []string{}
		for _, resource := range rule.Resources {
			if strings.Contains(resource, "/") {
				subResourceEntries = append(subResourceEntries, resource)
			} else {
				regularEntries = append(regularEntries, resource)
			}
		}

		// build a condition for subresources
		var subResourceCondition ast.Node
		if len(subResourceEntries) > 0 {
			for i, resource := range subResourceEntries {
				if i == 0 {
					subResourceCondition = conditionForResources(subResourceCondition, rbacv1.PolicyRule{
						Resources: []string{resource},
					})
				} else {
					subResourceCondition = subResourceCondition.Or(
						conditionForResources(emptyNode, rbacv1.PolicyRule{
							Resources: []string{resource},
						}),
					)
				}
			}
		}

		var resourceCondition ast.Node
		regularEntryResources := []ast.Node{}
		for _, resource := range regularEntries {
			regularEntryResources = append(regularEntryResources, ast.String(resource))
		}
		if len(regularEntryResources) == 1 {
			resourceCondition = ast.Resource().Access("resource").Equal(regularEntryResources[0])
		} else if len(regularEntryResources) > 1 {
			resourceCondition = ast.Set(regularEntryResources...).Contains(ast.Resource().Access("resource"))
		}

		// OR the subresource condition with restouces if it exists
		if subResourceCondition != emptyNode && resourceCondition != emptyNode {
			resourceCondition = resourceCondition.Or(subResourceCondition)
		} else if subResourceCondition != emptyNode && resourceCondition == emptyNode {
			// if there are only subresources, use that as the condition
			resourceCondition = subResourceCondition
		}
		if condition != emptyNode {
			// AND the resource condition with the existing policy conditions
			condition = condition.And(resourceCondition)
		} else {
			condition = resourceCondition
		}
	}
	return condition
}

// RBAC doesn't allow globs in names, so we're safe to always use `Equal()` or `Set().Contains()`
func conditionForResourceNames(condition ast.Node, rule rbacv1.PolicyRule) ast.Node {
	if len(rule.ResourceNames) == 1 {
		condition = condition.And(
			ast.Resource().Has("name").And(
				ast.Resource().Access("name").Equal(ast.String(rule.ResourceNames[0])),
			),
		)
	} else if len(rule.ResourceNames) > 1 {
		resourceNames := []ast.Node{}
		for _, resourceName := range rule.ResourceNames {
			resourceNames = append(resourceNames, ast.String(resourceName))
		}
		condition = condition.And(
			ast.Resource().Has("name").And(
				ast.Set(resourceNames...).Contains(ast.Resource().Access("name")),
			),
		)
	}
	return condition
}
