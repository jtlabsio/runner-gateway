package interfaces

import "github.com/valyala/fasthttp"

type AuthorizationService interface {
	AuthorizeRequest(next fasthttp.RequestHandler) fasthttp.RequestHandler
	GenerateAsymmetricKeyPair() (string, string, error)
	GeneratePublicPASETO() (string, error)
	GeneratePrivatePASETO() (string, error)
	GenerateSymmetricKey() string
	ValidateToken(token string) error
}

type GatewayService interface {
	ForwardRequest(hst string, pth string, schm string) func(*fasthttp.RequestCtx)
}
