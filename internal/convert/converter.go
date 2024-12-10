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

			rule.Verbs = reduceIfHasStar(uniqueElements(rule.Verbs))

			// '*' verb encompasses all actions, so no action specification required
			if len(rule.Verbs) == 1 && rule.Verbs[0] != "*" {
				policy = policy.ActionEq(cedartypes.EntityUID{
					Type: schema.AuthorizationActionEntityType,
					ID:   cedartypes.String(rule.Verbs[0]),
				})
			} else if len(rule.Verbs) > 1 {
				actions := []cedartypes.EntityUID{}
				for _, verb := range rule.Verbs {
					actions = append(actions, cedartypes.NewEntityUID(schema.AuthorizationActionEntityType, cedartypes.String(verb)))
				}
				policy = policy.ActionInSet(actions...)
			}

			if len(rule.NonResourceURLs) > 0 {
				policy = policy.ResourceIs(schema.NonResourceURLEntityType)
				policy = policyWhenCondition(policy, conditionForNonResourceURLs(rule), emptyNode)
				policyId := cedar.PolicyID(binder.Name() + strconv.Itoa(pi) + strconv.Itoa(ri))
				resp.Add(policyId, cedar.NewPolicyFromAST(policy))
				continue
			}

			if (rule.Verbs[0] == "*" && rule.Resources[0] == "*" && rule.APIGroups[0] == "*") || (slices.Contains(rule.Verbs, "impersonate") && slices.Contains(rule.APIGroups, "authentication.k8s.io")) {
				impersonationPolicy := grossCopyPolicy(policy)
				impersonationPolicy = impersonationPolicy.ActionEq(cedartypes.EntityUID{
					Type: schema.AuthorizationActionEntityType,
					ID:   cedartypes.String("impersonate"),
				})
				impersonationPolicy, condition := policyForImpersonate(impersonationPolicy, rule)
				impersonationPolicy = policyWhenCondition(impersonationPolicy, condition, when)

				policyId := cedar.PolicyID(binder.Name() + ":" + binder.Type() + "/impersonate" + ":" + strconv.Itoa(pi) + strconv.Itoa(ri))
				resp.Add(policyId, cedar.NewPolicyFromAST(impersonationPolicy))

				if len(rule.Verbs) == 1 && rule.Verbs[0] == "impersonate" {
					// Skip resource rules for impersonate-only verb
					continue
				}
			}

			rule.APIGroups = reduceIfHasStar(uniqueElements(rule.APIGroups))
			rule.Resources = reduceIfHasStar(uniqueElements(rule.Resources))
			rule.ResourceNames = uniqueElements(rule.ResourceNames)
			// RBAC doesn't allow "*" as a resource name: empty slice means "*"

			condition := conditionForAPIGroups(rule)
			condition = conditionForResources(condition, rule)
			condition = conditionForResourceNames(condition, rule)

			if namespace != "" {
				condition = conditionAnd(
					condition,
					ast.Resource().Has("namespace").And(
						ast.Resource().Access("namespace").Equal(ast.String(namespace)),
					),
				)
			}

			policy = policyWhenCondition(policy, condition, when)

			// if no subresources
			if !hasSubResources(rule) {
				policy = policy.Unless(ast.Resource().Has("subresource"))
			}

			policy = policy.ResourceIs(schema.ResourceEntityType)
			policyId := cedar.PolicyID(binder.Name() + ":" + binder.Type() + ":" + strconv.Itoa(pi) + strconv.Itoa(ri))
			resp.Add(policyId, cedar.NewPolicyFromAST(policy))
		}
		pi += 1
	}
	return resp
}

// grossCopyPolicy serializes an *ast.Cedar policy to serialized Cedar, and unmarshals that to a new *ast.Policy.
// This is useful for a deep copy of a policy.
func grossCopyPolicy(policy *ast.Policy) *ast.Policy {
	p := cedar.NewPolicyFromAST(policy)
	cp := &cedar.Policy{}
	_ = cp.UnmarshalCedar(p.MarshalCedar())
	return cp.AST()
}

// policyWhenCondition adds a `when {}` clause to a policy by ANDing the condition and when nodes, if they're present
func policyWhenCondition(policy *ast.Policy, condition, when ast.Node) *ast.Policy {
	if n := conditionAnd(when, condition); n != emptyNode {
		return policy.When(n)
	}
	return policy
}

// conditionOr returns an `lhs.Or(rhs)` if both nodes are not empty, otherwise
// just returns the non empty node. If both are empty, returns an empty node.
func conditionOr(lhs ast.Node, rhs ast.Node) ast.Node {
	if lhs != emptyNode {
		if rhs != emptyNode {
			return lhs.Or(rhs)
		}
		return lhs
	}
	return rhs
}

// conditionAnd returns an `lhs.And(rhs)` if both nodes are not empty, otherwise
// just returns the non empty node. If both are empty, returns an empty node.
func conditionAnd(lhs ast.Node, rhs ast.Node) ast.Node {
	if lhs != emptyNode {
		if rhs != emptyNode {
			return lhs.And(rhs)
		}
		return lhs
	}
	return rhs
}

// stringSliceToSet returns an ast.Set() for a given strin slice
func stringSliceToSet(slice []string) ast.Node {
	elements := []ast.Node{}
	for _, s := range slice {
		elements = append(elements, ast.String(s))
	}
	return ast.Set(elements...)
}

// uniqueElements returns a slice of deduplicated items.
// Only the first of any duplicate is included, in order.
func uniqueElements(slice []string) []string {
	unique := []string{}
	for _, s := range slice {
		if !slices.Contains(unique, s) {
			unique = append(unique, s)
		}
	}
	return unique
}

// reduceIfHasStar returns a `*` minus all other entries if `*` is present
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
			return ast.Resource().Access("path").Like(cedartypes.NewPattern(rule.NonResourceURLs[0]))
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
	for wi := range wildCardUrls {
		condition = conditionOr(
			condition,
			ast.Resource().Access("path").Like(cedartypes.NewPattern(wildCardUrls[wi])),
		)
	}
	if len(nonWildCardUrls) == 1 {
		condition = conditionOr(condition, ast.Resource().Access("path").Equal(ast.String(nonWildCardUrls[0])))
	} else if len(nonWildCardUrls) > 1 {
		condition = conditionOr(condition, stringSliceToSet(nonWildCardUrls).Contains(ast.Resource().Access("path")))
	}
	return condition
}

func conditionForAPIGroups(rule rbacv1.PolicyRule) ast.Node {
	condition := ast.Resource().Access("apiGroup").Equal(ast.String(rule.APIGroups[0]))
	if len(rule.APIGroups) == 1 && rule.APIGroups[0] == "*" {
		return emptyNode
	}
	if len(rule.APIGroups) > 1 {
		condition = stringSliceToSet(rule.APIGroups).Contains(ast.Resource().Access("apiGroup"))
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

func policyForImpersonate(policy *ast.Policy, rule rbacv1.PolicyRule) (*ast.Policy, ast.Node) {
	var condition ast.Node

	allSameResourceType := true
	r0 := rule.Resources[0]
	for _, r := range rule.Resources {
		if strings.HasPrefix(r0, "userextras") {
			if !strings.HasPrefix(r, "userextras") {
				allSameResourceType = false
				break
			}
			continue
		}
		if r != r0 {
			allSameResourceType = false
			break
		}
	}

	if allSameResourceType {
		switch rule.Resources[0] {
		case "users":
			policy = policy.ResourceIs(schema.UserEntityType)
			condition = conditionForNamedGroupUserImpersonation(condition, rule)
		case "groups":
			policy = policy.ResourceIs(schema.GroupEntityType)
			condition = conditionForNamedGroupUserImpersonation(condition, rule)
		case "uids":
			policy = policy.ResourceIs(schema.PrincipalUIDEntityType)
			condition = conditionForUidImpersonation(condition, rule)
			if len(rule.ResourceNames) == 1 {
				policy = policy.ResourceEq(cedartypes.EntityUID{
					Type: schema.PrincipalUIDEntityType,
					ID:   cedartypes.String(rule.ResourceNames[0]),
				})
				return policy, condition
			}
		}
		if strings.HasPrefix(rule.Resources[0], "userextras") {
			policy = policy.ResourceIs(schema.ExtraValueEntityType)
			condition = conditionForExtraImpersonation(condition, rule)
		}
		return policy, condition
	}
	for _, resource := range rule.Resources {
		var localCondition ast.Node
		switch resource {
		case "users":
			localCondition = ast.Resource().Is(schema.UserEntityType)
			localCondition = conditionForNamedGroupUserImpersonation(localCondition, rule)
		case "groups":
			localCondition = ast.Resource().Is(schema.GroupEntityType)
			localCondition = conditionForNamedGroupUserImpersonation(localCondition, rule)
		case "uids":
			localCondition = ast.Resource().Is(schema.PrincipalUIDEntityType)
			if len(rule.ResourceNames) == 1 {
				localCondition = ast.Resource().Equal(ast.EntityUID(
					cedartypes.Ident(schema.PrincipalUIDEntityType),
					cedartypes.String(rule.ResourceNames[0]),
				))
			}
			localCondition = conditionForUidImpersonation(localCondition, rule)
		}
		if strings.HasPrefix(resource, "userextras") {
			localCondition = ast.Resource().Is(schema.ExtraValueEntityType)
			localCondition = conditionForExtraImpersonation(localCondition, rule)
		}
		condition = conditionOr(localCondition, condition)
	}

	return policy, condition
}

func conditionForUidImpersonation(condition ast.Node, rule rbacv1.PolicyRule) ast.Node {
	if len(rule.ResourceNames) == 1 {
		return condition
	}

	entities := []ast.Node{}
	for _, name := range rule.ResourceNames {
		entities = append(entities, ast.EntityUID(
			cedartypes.Ident(schema.PrincipalUIDEntityType),
			cedartypes.String(name),
		))
	}

	return conditionAnd(condition, ast.Resource().In(ast.Set(entities...)))
}

func conditionForNamedGroupUserImpersonation(condition ast.Node, rule rbacv1.PolicyRule) ast.Node {
	if len(rule.ResourceNames) == 1 {
		return conditionAnd(condition, ast.Resource().Access("name").Equal(ast.String(rule.ResourceNames[0])))
	} else if len(rule.ResourceNames) > 1 {
		return conditionAnd(condition, stringSliceToSet(rule.ResourceNames).Contains(ast.Resource().Access("name")))
	}
	return condition
}

func conditionForExtraImpersonation(condition ast.Node, rule rbacv1.PolicyRule) ast.Node {
	impersonatedKeys := []string{}
	for _, resource := range rule.Resources {
		if strings.Contains(resource, "/") {
			impersonatedKeys = append(impersonatedKeys, strings.SplitN(resource, "/", 2)[1])
		}
	}

	if len(impersonatedKeys) == 1 {
		condition = conditionAnd(condition, ast.Resource().Access("key").Equal(ast.String(impersonatedKeys[0])))
	} else if len(impersonatedKeys) > 1 {
		condition = conditionAnd(condition, stringSliceToSet(impersonatedKeys).Contains(ast.Resource().Access("key")))
	}

	if len(rule.ResourceNames) == 1 {
		condition = conditionAnd(
			condition,
			ast.Resource().Has("value").And(
				ast.Resource().Access("value").Equal(ast.String(rule.ResourceNames[0])),
			),
		)
	} else if len(rule.ResourceNames) > 1 {
		condition = conditionAnd(
			condition,
			ast.Resource().Has("value").And(
				stringSliceToSet(rule.ResourceNames).Contains(ast.Resource().Access("value")),
			),
		)
	}
	return condition
}

func conditionForResources(condition ast.Node, rule rbacv1.PolicyRule) (when ast.Node) {
	if len(rule.Resources) == 1 {
		if rule.Resources[0] == "*" {
			// TODO: This is incorrect, we need to restrict this for named resources
			return condition
		}

		if !strings.Contains(rule.Resources[0], "/") {
			// handle single resource without subresource
			condition = conditionAnd(
				condition,
				ast.Resource().Access("resource").Equal(ast.String(rule.Resources[0])),
			)
		} else {
			// handle subresources
			left, right := strings.SplitN(rule.Resources[0], "/", 2)[0], strings.SplitN(rule.Resources[0], "/", 2)[1]

			// "*" means all .resources unconditionally, so no condition needed
			if left != "*" {
				condition = conditionAnd(condition, ast.Resource().Access("resource").Equal(ast.String(left)))
			}

			if right == "*" {
				// TODO: Do we need the `resource.subresource != ""` check? Or does presence mean non-empty?
				// Has subresource and subresource is not empty
				condition = conditionAnd(condition, ast.Resource().Has("subresource").And(ast.Resource().Access("subresource").NotEqual(ast.String(""))))
			} else {
				condition = conditionAnd(condition,
					ast.Resource().Has("subresource").And(
						ast.Resource().Access("subresource").Equal(ast.String(right)),
					),
				)
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
		if len(regularEntries) == 1 {
			resourceCondition = ast.Resource().Access("resource").Equal(ast.String(regularEntries[0]))
		} else if len(regularEntries) > 1 {
			resourceCondition = stringSliceToSet(regularEntries).Contains(ast.Resource().Access("resource"))
		}

		// OR the subresource condition with restouces if it exists.
		// If there are only subresources, use that as the condition
		condition = conditionAnd(
			condition,
			conditionOr(resourceCondition, subResourceCondition),
		)
	}
	return condition
}

// conditionForResourceNames returns a condition for resource names.
// RBAC doesn't allow globs in names, so we're safe to always use `Equal()` or `Set().Contains()`
func conditionForResourceNames(condition ast.Node, rule rbacv1.PolicyRule) ast.Node {
	if len(rule.ResourceNames) == 1 {
		condition = condition.And(
			ast.Resource().Has("name").And(
				ast.Resource().Access("name").Equal(ast.String(rule.ResourceNames[0])),
			),
		)
	} else if len(rule.ResourceNames) > 1 {
		condition = condition.And(
			ast.Resource().Has("name").And(
				stringSliceToSet(rule.ResourceNames).Contains(ast.Resource().Access("name")),
			),
		)
	}
	return condition
}
