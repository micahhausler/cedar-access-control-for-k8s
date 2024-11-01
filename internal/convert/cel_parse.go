package convert

import (
	"fmt"
	"os"
	"strings"

	cedarast "github.com/cedar-policy/cedar-go/ast"
	cedartypes "github.com/cedar-policy/cedar-go/types"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
)

func walkAST(expr ast.Expr, space int) (*cedarast.Node, error) {
	if expr == nil {
		return nil, nil
	}
	var when cedarast.Node
	prefix := strings.Repeat("  ", space)

	switch expr.Kind() {
	case ast.CallKind:
		caller := expr.AsCall()
		fmt.Fprintf(os.Stderr, prefix+"Function name: %s\n", caller.FunctionName())

		switch caller.FunctionName() {
		case "_||_":

			lhs, err := walkAST(caller.Args()[0], space+1)
			if err != nil {
				return nil, err
			}
			rhs, err := walkAST(caller.Args()[1], space+1)
			if err != nil {
				return nil, err
			}
			if lhs == nil || rhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v, rhs: %v\n", lhs, rhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			when = lhs.Or(*rhs)
		case "_&&_":

			lhs, err := walkAST(caller.Args()[0], space+1)
			if err != nil {
				return nil, err
			}
			rhs, err := walkAST(caller.Args()[1], space+1)
			if err != nil {
				return nil, err
			}
			if lhs == nil || rhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v, rhs: %v\n", lhs, rhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			when = lhs.And(*rhs)
		case "!_":
			node, err := walkAST(caller.Args()[0], space+1)
			if err != nil {
				return nil, err
			}
			if node == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: %v\n", node)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			when = cedarast.Not(*node)
		case "_==_":
			lhs, err := walkAST(caller.Args()[0], space+1)
			if err != nil {
				return nil, err
			}
			rhs, err := walkAST(caller.Args()[1], space+1)
			if err != nil {
				return nil, err
			}
			if lhs == nil || rhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v, rhs: %v\n", lhs, rhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			when = lhs.Equal(*rhs)

		case "_>_":
			lhs, err := walkAST(caller.Args()[0], space+1)
			if err != nil {
				return nil, err
			}
			rhs, err := walkAST(caller.Args()[1], space+1)
			if err != nil {
				return nil, err
			}
			if lhs == nil || rhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v, rhs: %v\n", lhs, rhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			when = lhs.GreaterThan(*rhs)

		case "_<_":
			lhs, err := walkAST(caller.Args()[0], space+1)
			if err != nil {
				return nil, err
			}
			rhs, err := walkAST(caller.Args()[1], space+1)
			if err != nil {
				return nil, err
			}
			if lhs == nil || rhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v, rhs: %v\n", lhs, rhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			when = lhs.LessThan(*rhs)

		case "_=>_":
			lhs, err := walkAST(caller.Args()[0], space+1)
			if err != nil {
				return nil, err
			}
			rhs, err := walkAST(caller.Args()[1], space+1)
			if err != nil {
				return nil, err
			}
			if lhs == nil || rhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v, rhs: %v\n", lhs, rhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			when = lhs.GreaterThanOrEqual(*rhs)

		case "_<=_":
			lhs, err := walkAST(caller.Args()[0], space+1)
			if err != nil {
				return nil, err
			}
			rhs, err := walkAST(caller.Args()[1], space+1)
			if err != nil {
				return nil, err
			}
			if lhs == nil || rhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v, rhs: %v\n", lhs, rhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			when = lhs.LessThanOrEqual(*rhs)
		case "size":
			return nil, fmt.Errorf("cedar doesn't support a len/size function")
		case "startsWith":
			lhs, err := walkAST(caller.Target(), space+1)
			if err != nil {
				return nil, err
			}
			var rhs cedartypes.Pattern
			switch caller.Args()[0].Kind() {
			case ast.LiteralKind:
				rhs = cedartypes.NewPattern(caller.Args()[0].AsLiteral().Value().(string), cedartypes.Wildcard{})
			default:
				return nil, fmt.Errorf("can only translate startsWith() using a literal")
			}
			if lhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v\n", lhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			when = lhs.Like(rhs)

		case "endsWith":
			lhs, err := walkAST(caller.Target(), space+1)
			if err != nil {
				return nil, err
			}
			if lhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v\n", lhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			var rhs cedartypes.Pattern
			switch caller.Args()[0].Kind() {
			case ast.LiteralKind:
				rhs = cedartypes.NewPattern(cedartypes.Wildcard{}, caller.Args()[0].AsLiteral().Value().(string))
			default:
				return nil, fmt.Errorf("can only translate endsWith() using a literal")
			}
			when = lhs.Like(rhs)
		case "contains":
			lhs, err := walkAST(caller.Target(), space+1)
			if err != nil {
				return nil, err
			}
			if lhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v\n", lhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			var rhs cedartypes.Pattern
			switch caller.Args()[0].Kind() {
			case ast.LiteralKind:
				rhs = cedartypes.NewPattern(cedartypes.Wildcard{}, caller.Args()[0].AsLiteral().Value().(string), cedartypes.Wildcard{})
			default:
				return nil, fmt.Errorf("can only translate string contains() using a literal")
			}
			when = lhs.Like(rhs)
		case "@in":
			lhs, err := walkAST(caller.Args()[0], space+1)
			if err != nil {
				return nil, err
			}
			rhs, err := walkAST(caller.Args()[1], space+1)
			if err != nil {
				return nil, err
			}
			if lhs == nil && rhs == nil {
				fmt.Fprintf(os.Stderr, prefix+"Skipping for nil node: lhs: %v, rhs: %v\n", lhs, rhs)
				return nil, fmt.Errorf("skipping function %s for nil node", caller.FunctionName())
			}
			when = rhs.Contains(*lhs)
		case "_?_:_":
			conditionNode, err := walkAST(caller.Args()[0], space+1)
			if err != nil {
				return nil, err
			}
			thenNode, err := walkAST(caller.Args()[1], space+1)
			if err != nil {
				return nil, err
			}
			elseNode, err := walkAST(caller.Args()[2], space+1)
			if err != nil {
				return nil, err
			}
			when = cedarast.IfThenElse(*conditionNode, *thenNode, *elseNode)
		default:
			fmt.Fprintf(os.Stderr, prefix+"Unknown function: %s\n", caller.FunctionName())
			return nil, fmt.Errorf("unknown function: %s", caller.FunctionName())
		}
	case ast.ComprehensionKind:
		return nil, fmt.Errorf("comprehension not implemented by cedar")
	case ast.IdentKind:
		id := expr.AsIdent()
		fmt.Fprintf(os.Stderr, prefix+"Identifier: %s\n", id)
		switch id {
		case "object":
			when = cedarast.Resource()
		default:
			when = cedarast.Context().Access(cedartypes.String(id))
		}
	case ast.ListKind:
		nodes := []cedarast.Node{}
		for _, e := range expr.AsList().Elements() {
			n, err := walkAST(e, space+1)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, *n)
		}
		when = cedarast.Set(nodes...)
	case ast.LiteralKind:
		literal := expr.AsLiteral()
		switch literal.Value().(type) {
		case bool:
			when = cedarast.Boolean(literal.Value().(bool))
		case int:
			when = cedarast.Long(literal.Value().(int))
		case int64:
			when = cedarast.Long(literal.Value().(int64))
		case string:
			when = cedarast.String(literal.Value().(string))
		default:
			fmt.Fprintf(os.Stderr, prefix+"Unknown literal type: %T %v\n", literal.Value(), literal.Value())
		}
	case ast.MapKind:
		return nil, fmt.Errorf("comprehension not yet implemented")
	case ast.SelectKind:
		selector := expr.AsSelect()
		operandNode, err := walkAST(selector.Operand(), space+1)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, prefix+"Selector. Field Name: %v, Operand %#v \n", selector.FieldName(), operandNode)
		if selector.IsTestOnly() {
			when = operandNode.Has(cedartypes.String(selector.FieldName()))
		} else {
			when = operandNode.Access(cedartypes.String(selector.FieldName()))
		}
	case ast.StructKind:
		fmt.Fprintf(os.Stderr, prefix+"Struct of type %s \n", expr.AsStruct().TypeName())
		return nil, fmt.Errorf("struct not yet implemented")
	default:
		fmt.Fprintf(os.Stderr, prefix+"Unknown expression kind: %v\n", expr.Kind())
		return nil, fmt.Errorf("unknown expression kind: %v", expr.Kind())
	}
	if when == emptyNode {
		return nil, nil
	}

	return &when, nil
}

func ParseCEL(expression string) (*cedarast.Node, error) {
	env, err := cel.NewEnv(
		cel.Variable("object", cel.AnyType),
		cel.Variable("params", cel.AnyType),
	)
	if err != nil {
		return nil, err
	}

	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, err
	}

	return walkAST(ast.NativeRep().Expr(), 0)
}
