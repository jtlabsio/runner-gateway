package interfaces

import "github.com/valyala/fasthttp"

type AuthorizationService interface {
	AuthorizeRequest(next fasthttp.RequestHandler) fasthttp.RequestHandler
	GenerateAsymmetricKeyPair() (string, string)
	GeneratePublicPASETO() (string, error)
	GeneratePrivatePASETO() (string, error)
	GenerateSymmetricKey() string
	ValidateToken(token []byte) bool
}

type GatewayService interface {
	ForwardRequest(hst string, pth string, schm string) func(*fasthttp.RequestCtx)
}
