package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/traits"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

type externalClaimsResolver struct {
	// TODO implement
	clientAuthentication clientAuthentication
	claims               []externalClaim
	tls                  TLS
}

func (ecr *externalClaimsResolver) expand(ctx context.Context, token string, c claims) error {
	// TODO: implement some kind of support for client credential and access token client authentication methods.
	// For now, just use the token being authenticated.
	accessToken := token

	for _, claim := range ecr.claims {
		// TODO: implement support for evaluating external claim sourcing conditions
		url, err := claim.getURLWithClaims(ctx, c)
		if err != nil {
			return fmt.Errorf("oidc: error during external claims resolution: building external claims URL: %w", err)
		}

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("oidc: error during external claims resolution: building external claims request: %w", err)
		}

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("oidc: error during external claims resolution: performing external claims request: %w", err)
		}

		externalClaims, err := claim.getClaimsFromResponse(ctx, resp)
		if err != nil {
			return fmt.Errorf("oidc: error during external claims resolution: getting claims from response: %w", err)
		}

		for name, value := range externalClaims {
			c[name] = value
		}
	}

	return nil
}

type clientAuthentication struct {
	clientCredential clientCredential
	accessToken      string
}

type clientCredential struct {
	id            string
	secret        string
	tokenEndpoint string
}

type externalClaim struct {
	celMapper externalClaimCELMapper
}

func (ec *externalClaim) getURLWithClaims(ctx context.Context, c claims) (string, error) {
	evaluationResults, err := ec.celMapper.URL.PathExpression.EvalClaimMapping(ctx, newClaimsValue(c))
	if err != nil {
		return "", fmt.Errorf("oidc: error evaluating path expression: %w", err)
	}

	if evaluationResults.EvalResult.Type() != cel.StringType {
		return "", fmt.Errorf("oidc: error evaluating path expression: %w", fmt.Errorf("path expression must return a string"))
	}

	path := evaluationResults.EvalResult.Value().(string)

	urlStr := fmt.Sprintf("%s/%s", ec.celMapper.URL.Base, path)

	return urlStr, nil
}

func (ec *externalClaim) getClaimsFromResponse(ctx context.Context, resp *http.Response) (claims, error) {
	externalClaims := claims{}

	responseBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	input := map[string]any{}
	err = json.Unmarshal(responseBodyBytes, &input)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response body: %w", err)
	}

	for claim, mapper := range ec.celMapper.Mappings {
		evalResult, err := mapper.EvalResponse(ctx, types.NewStringInterfaceMap(types.DefaultTypeAdapter, input))
		if err != nil {
			fmt.Printf("error evaluating external claim mapping %q: %w\n", claim, err)
			return nil, fmt.Errorf("error evaluating external claim mapping %q: %w\n", claim, err)
		}

		if evalResult.EvalResult.Type() != cel.StringType {
			return nil, fmt.Errorf("error evaluating external claim mapping %q: %w", claim, errors.New("expected a string return type"))
		}

		externalClaims[claim] = json.RawMessage(evalResult.EvalResult.Value().(string))
	}

	return externalClaims, nil
}

type externalClaimCELMapper struct {
	URL        urlCELMapper
	Mappings   map[string]ExternalSourceResponseMapper
	Conditions authenticationcel.ClaimsMapper
}

type urlCELMapper struct {
	Base           string
	PathExpression authenticationcel.ClaimsMapper
}

type externalClaimMapping struct {
	name       string
	expression string
}

type externalClaimCondition struct {
	expression string
}

type TLS struct {
	certificateAuthority string
}

type ExternalSourceResponseMapper interface {
	EvalResponse(context.Context, traits.Mapper) (authenticationcel.EvaluationResult, error)
}
