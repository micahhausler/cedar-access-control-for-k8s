package convert

import (
	rbacv1 "k8s.io/api/rbac/v1"
)

// Identifier is an interface for identifying RBAC types and names
type Identifier interface {
	Name() string
	Type() string
}

// Ruler is an interface for getting rules from a RBAC type
type Ruler interface {
	Rules() []rbacv1.PolicyRule
	Identifier
}

// Binder is an interface for getting subjects from an RBAC type
type Binder interface {
	Subjects() []rbacv1.Subject
	Identifier
}

type crRuler struct{ cr rbacv1.ClusterRole }

func (c *crRuler) Rules() []rbacv1.PolicyRule         { return c.cr.Rules }
func (c *crRuler) Name() string                       { return c.cr.Name }
func (c *crRuler) Type() string                       { return "clusterRole" }
func NewClusterRoleRuler(cr rbacv1.ClusterRole) Ruler { return &crRuler{cr: cr} }

type crbBinder struct{ crb rbacv1.ClusterRoleBinding }

func (c *crbBinder) Subjects() []rbacv1.Subject                 { return c.crb.Subjects }
func (c *crbBinder) Name() string                               { return c.crb.Name }
func (c *crbBinder) Type() string                               { return "clusterRoleBinding" }
func NewClusterRoleBinder(crb rbacv1.ClusterRoleBinding) Binder { return &crbBinder{crb: crb} }

type roleRuler struct{ r rbacv1.Role }

func (r *roleRuler) Rules() []rbacv1.PolicyRule { return r.r.Rules }
func (r *roleRuler) Name() string               { return r.r.Name }
func (r *roleRuler) Type() string               { return "role" }
func NewRoleRuler(r rbacv1.Role) Ruler          { return &roleRuler{r: r} }

type rbBinder struct{ rb rbacv1.RoleBinding }

func (r *rbBinder) Subjects() []rbacv1.Subject   { return r.rb.Subjects }
func (r *rbBinder) Name() string                 { return r.rb.Name }
func (r *rbBinder) Type() string                 { return "roleBinding" }
func NewRoleBinder(rb rbacv1.RoleBinding) Binder { return &rbBinder{rb: rb} }
