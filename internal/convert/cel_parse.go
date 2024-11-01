package convert

import (
	"fmt"
	"os"

	cedarast "github.com/cedar-policy/cedar-go/ast"
	cedartypes "github.com/cedar-policy/cedar-go/types"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/ext"
)

// pulled from
// https://kubernetes.io/docs/reference/using-api/cel/
// https://github.com/kubernetes/kubernetes/blob/v1.31.1/staging/src/k8s.io/apiserver/pkg/cel/environment/base.go#L61
func ParseCEL(expression string) (*cedarast.Node, error) {
	env, err := cel.NewEnv(
		cel.Variable("object", cel.AnyType),
		cel.Variable("params", cel.AnyType),
		cel.EagerlyValidateDeclarations(true),
		cel.DefaultUTCTimeZone(true),
		cel.HomogeneousAggregateLiterals(),
		ext.Strings(ext.StringsVersion(2)), // K8s v1.29+
	)
	if err != nil {
		return nil, err
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, err
	}
	return walkAST(ast.NativeRep().Expr())
}

type funcParser func(ast.CallExpr) (*cedarast.Node, error)

func callerTwoArgs(caller ast.CallExpr) (lhs *cedarast.Node, rhs *cedarast.Node, err error) {
	lhs, err = walkAST(caller.Args()[0])
	if err != nil {
		return nil, nil, err
	}
	rhs, err = walkAST(caller.Args()[1])
	if err != nil {
		return nil, nil, err
	}
	if lhs == nil || rhs == nil {
		return nil, nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
	}
	return lhs, rhs, nil
}

func parseOr(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := lhs.Or(*rhs)
	return &resp, nil
}

func parseAnd(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := lhs.And(*rhs)
	return &resp, nil
}

func parseNot(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, err := walkAST(caller.Args()[0])
	if err != nil {
		return nil, err
	}
	if lhs == nil {
		return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
	}
	resp := cedarast.Not(*lhs)
	return &resp, nil
}

func parseEq(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := lhs.Equal(*rhs)
	return &resp, nil
}

func parseNotEq(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := lhs.NotEqual(*rhs)
	return &resp, nil
}
func parseGt(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := lhs.GreaterThan(*rhs)
	return &resp, nil
}

func parseLt(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := lhs.LessThan(*rhs)
	return &resp, nil
}
func parseGtEq(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := lhs.GreaterThanOrEqual(*rhs)
	return &resp, nil
}

func parseLtEq(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := lhs.LessThanOrEqual(*rhs)
	return &resp, nil
}

func parseStartsWith(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, err := walkAST(caller.Target())
	if err != nil {
		return nil, err
	}
	if lhs == nil {
		return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
	}
	var rhs cedartypes.Pattern
	switch caller.Args()[0].Kind() {
	case ast.LiteralKind:
		rhs = cedartypes.NewPattern(caller.Args()[0].AsLiteral().Value().(string), cedartypes.Wildcard{})
	default:
		return nil, fmt.Errorf("can only translate endsWith() using a literal")
	}
	resp := lhs.Like(rhs)
	return &resp, nil
}

func parseEndsWith(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, err := walkAST(caller.Target())
	if err != nil {
		return nil, err
	}
	if lhs == nil {
		return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
	}
	var rhs cedartypes.Pattern
	switch caller.Args()[0].Kind() {
	case ast.LiteralKind:
		rhs = cedartypes.NewPattern(cedartypes.Wildcard{}, caller.Args()[0].AsLiteral().Value().(string))
	default:
		return nil, fmt.Errorf("can only translate endsWith() using a literal")
	}
	resp := lhs.Like(rhs)
	return &resp, nil
}

func parseStrContains(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, err := walkAST(caller.Target())
	if err != nil {
		return nil, err
	}
	if lhs == nil {
		return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
	}
	var rhs cedartypes.Pattern
	switch caller.Args()[0].Kind() {
	case ast.LiteralKind:
		rhs = cedartypes.NewPattern(cedartypes.Wildcard{}, caller.Args()[0].AsLiteral().Value().(string), cedartypes.Wildcard{})
	default:
		return nil, fmt.Errorf("can only translate string contains() using a literal")
	}
	resp := lhs.Like(rhs)
	return &resp, nil
}

func parseIn(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := rhs.Contains(*lhs)
	return &resp, nil
}

func parseCondition(caller ast.CallExpr) (*cedarast.Node, error) {
	conditionNode, err := walkAST(caller.Args()[0])
	if err != nil {
		return nil, err
	}
	thenNode, err := walkAST(caller.Args()[1])
	if err != nil {
		return nil, err
	}
	elseNode, err := walkAST(caller.Args()[2])
	if err != nil {
		return nil, err
	}
	resp := cedarast.IfThenElse(*conditionNode, *thenNode, *elseNode)
	return &resp, nil
}

func parseAddition(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := rhs.Add(*lhs)
	return &resp, nil
}

func parseSubtraction(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := rhs.Subtract(*lhs)
	return &resp, nil
}

func parseMultiplication(caller ast.CallExpr) (*cedarast.Node, error) {
	lhs, rhs, err := callerTwoArgs(caller)
	if err != nil {
		return nil, err
	}
	resp := rhs.Multiply(*lhs)
	return &resp, nil
}

func parseMap(mapper ast.MapExpr) (*cedarast.Node, error) {
	pairs := cedarast.Pairs{}
	for _, field := range mapper.Entries() {
		switch field.Kind() {
		case ast.MapEntryKind:
			me := field.AsMapEntry()
			key, err := walkAST(me.Key())
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, cedarast.Pair{
				Key:   "key",
				Value: *key,
			})

			value, err := walkAST(me.Value())
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, cedarast.Pair{
				Key:   "value",
				Value: *value,
			})

		case ast.StructFieldKind:
			sf := field.AsStructField()
			value, err := walkAST(sf.Value())
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, cedarast.Pair{
				Key:   cedartypes.String(sf.Name()),
				Value: *value,
			})
		case ast.UnspecifiedEntryExprKind:
			return nil, fmt.Errorf("unspecified entry expression kind: %v", field.Kind())
		}
	}
	resp := cedarast.Record(pairs)
	return &resp, nil
}

// TODO: Implement max depth?
func walkAST(expr ast.Expr) (*cedarast.Node, error) {
	if expr == nil {
		return nil, nil
	}
	var when *cedarast.Node
	switch expr.Kind() {
	case ast.CallKind:
		caller := expr.AsCall()
		var (
			parser funcParser
			err    error
		)
		switch caller.FunctionName() {
		case "_||_":
			parser = parseOr
		case "_&&_":
			parser = parseAnd
		case "!_":
			parser = parseNot
		case "_!=_":
			parser = parseNotEq
		case "_==_":
			parser = parseEq
		case "_>_":
			// TODO: neither the CEL AST nor Cedar AST gives us enough information to know
			// what the underlying node type is. We can't tell if it's a cedar decimal or long.
			fmt.Fprintf(os.Stderr, "Warning: validate use of > operator, should use .greaterThan() for decimals\n")
			parser = parseGt
		case "_<_":
			// TODO: neither the CEL AST nor Cedar AST gives us enough information to know
			// what the underlying node type is. We can't tell if it's a cedar decimal or long.
			fmt.Fprintf(os.Stderr, "Warning: validate use of < operator, should use .lessThan() for decimals\n")
			parser = parseLt
		case "_=>_":
			// TODO: neither the CEL AST nor Cedar AST gives us enough information to know
			// what the underlying node type is. We can't tell if it's a cedar decimal or long.
			fmt.Fprintf(os.Stderr, "Warning: validate use of => operator, should use .greaterThanOrEqual() for decimals\n")
			parser = parseGtEq
		case "_<=_":
			// TODO: neither the CEL AST nor Cedar AST gives us enough information to know
			// what the underlying node type is. We can't tell if it's a cedar decimal or long.
			fmt.Fprintf(os.Stderr, "Warning: validate use of <= operator, should use .lessThanOrEqual() for decimals\n")
			parser = parseLtEq
		case "startsWith":
			parser = parseStartsWith
		case "endsWith":
			parser = parseEndsWith
		case "contains":
			parser = parseStrContains
		case "@in":
			parser = parseIn
		case "_?_:_":
			parser = parseCondition
		case "_+_":
			parser = parseAddition
		case "_-_":
			parser = parseSubtraction
		case "_*_":
			parser = parseMultiplication
		case "double":
			return nil, fmt.Errorf("cedar-go AST package doesn't yet support decimal() conversion: requires manual translation")
		case "_/_":
			return nil, fmt.Errorf("cedar doesn't support division")
		case "size":
			return nil, fmt.Errorf("cedar doesn't support a len/size function")
		case "_[_]":
			return nil, fmt.Errorf("cedar doesn't support array indexing")
		case "matches":
			return nil, fmt.Errorf("cedar doesn't support RE2 matching")
		default:
			return nil, fmt.Errorf("unknown function: %s", caller.FunctionName())
		}
		when, err = parser(caller)
		if err != nil {
			return nil, err
		}
	case ast.ComprehensionKind:
		return nil, fmt.Errorf("cedar doesn't support comprehensions")
	case ast.IdentKind:
		id := expr.AsIdent()
		var node cedarast.Node
		switch id {
		case "object":
			node = cedarast.Resource()
		default:
			node = cedarast.Context().Access(cedartypes.String(id))
		}
		when = &node
	case ast.ListKind:
		nodes := []cedarast.Node{}
		for _, e := range expr.AsList().Elements() {
			n, err := walkAST(e)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, *n)
		}
		node := cedarast.Set(nodes...)
		when = &node
	case ast.LiteralKind:
		literal := expr.AsLiteral()
		var node cedarast.Node
		switch literal.Value().(type) {
		case bool:
			node = cedarast.Boolean(literal.Value().(bool))
		case int:
			node = cedarast.Long(literal.Value().(int))
		case int64:
			node = cedarast.Long(literal.Value().(int64))
		case float64:
			fmt.Fprintf(os.Stderr, "Warning: possibly truncating decimal: %v\n", literal.Value())
			node = cedarast.Value(cedartypes.UnsafeDecimal(literal.Value().(float64)))
		case string:
			node = cedarast.String(literal.Value().(string))
		case []uint8:
			node = cedarast.String(string(literal.Value().([]uint8)))
		default:
			return nil, fmt.Errorf("unknown literal type: %T %v", literal.Value(), literal.Value())
		}
		when = &node
	case ast.MapKind:
		return parseMap(expr.AsMap())
	case ast.SelectKind:
		selector := expr.AsSelect()
		operandNode, err := walkAST(selector.Operand())
		if err != nil {
			return nil, err
		}
		actorNode := *operandNode
		if selector.IsTestOnly() {
			actorNode = actorNode.Has(cedartypes.String(selector.FieldName()))
		} else {
			actorNode = actorNode.Access(cedartypes.String(selector.FieldName()))
		}
		when = &actorNode
	case ast.StructKind:
		return nil, fmt.Errorf("struct not yet implemented")
	default:
		return nil, fmt.Errorf("unknown expression kind: %v", expr.Kind())
	}
	return when, nil
}
