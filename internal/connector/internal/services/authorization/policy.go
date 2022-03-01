package authorization

import (
	"context"
	_ "embed"
	"github.com/open-policy-agent/opa/rego"
)

//go:embed connectors-authz.rego
var connectorsAuthzRego string

type ConnectorsAuthzService interface {
}

var _ ConnectorsAuthzService = &connectorsAuthzService{}

type connectorsAuthzService struct {
	query rego.PreparedEvalQuery
}

func NewConnectorsAuthzService() (*connectorsAuthzService, *error) {
	query, err := rego.New(
		rego.Query("allow"),
		rego.Module("connectors-authz.rego", connectorsAuthzRego),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, &err
	}
	return &connectorsAuthzService{
		query: query,
	}, nil
}

func init() {
}