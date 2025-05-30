package services

import (
	"os"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
	"go.jtlabs.io/runner-gateway/internal/models"
)

type authorizationService struct {
	log zerolog.Logger
	s   *models.Settings
}

func (a *authorizationService) newToken() paseto.Token {
	n := time.Now()

	// generate a new token
	tkn := paseto.NewToken()
	tkn.SetIssuedAt(n)
	tkn.SetNotBefore(n)
	tkn.SetExpiration(n.Add(a.s.PASETO.Expiration))

	return tkn
}

func (a *authorizationService) readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func NewAuthorizationService(s *models.Settings) *authorizationService {
	return &authorizationService{
		log: log.With().Str("service", "gateway").Logger(),
		s:   s,
	}
}

func (a *authorizationService) AuthorizeRequest(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		a.log.Trace().
			Str("uri", string(ctx.RequestURI())).
			Msg("Authorizing request")

		// validate Authorization
		tkn := ctx.Request.Header.Peek("Authorization")
		if tkn == nil {
			ctx.Error("Missing authorization error", fasthttp.StatusUnauthorized)
			return
		}

		// validate token
		if vld := a.ValidateToken(tkn); !vld {
			ctx.Error("Invalid authorization error", fasthttp.StatusUnauthorized)
			return
		}

		next(ctx)
	}
}

func (a *authorizationService) GenerateAsymmetricKeyPair() (string, string) {
	a.log.Trace().Msg("Generating asymmetric key pair")
	asym := paseto.NewV4AsymmetricSecretKey()

	a.log.Debug().
		Str("public", asym.Public().ExportHex()).
		Msg("Generated public PASETO token")

	return asym.ExportHex(), asym.Public().ExportHex()
}

func (a *authorizationService) GeneratePrivatePASETO() (string, error) {
	a.log.Trace().Msg("Generating PASETO token")
	sk, err := paseto.V4SymmetricKeyFromHex(a.s.PASETO.SecretKey)
	if err != nil {
		a.log.Error().Err(err).Msg("Failed to create symmetric key from hex")
		return "", err
	}

	tkn := a.newToken()
	enc := tkn.V4Encrypt(sk, nil)

	a.log.Debug().
		Str("paseto", enc).
		Msg("Generated private PASETO token")

	return enc, nil
}

func (a *authorizationService) GeneratePublicPASETO() (string, error) {
	a.log.Trace().Msg("Generating PASETO token")

	// load the secret key from file for signing
	key, err := a.readFile(a.s.PASETO.KeyPath)
	if err != nil {
		a.log.Error().Err(err).Msg("Failed to read secret key file")
		return key, err
	}

	ak, err := paseto.NewV4AsymmetricSecretKeyFromHex(key)
	if err != nil {
		a.log.Error().Err(err).Msg("Failed to create secret key from hex")
		return "", err
	}

	// generate and sign the new token
	tkn := a.newToken()
	sgn := tkn.V4Sign(ak, nil)

	a.log.Debug().
		Str("paseto", sgn).
		Msg("Generated public PASETO token")

	return sgn, nil
}

func (a *authorizationService) GenerateSymmetricKey() string {
	a.log.Trace().Msg("Generating symmetric key")
	sym := paseto.NewV4SymmetricKey()

	a.log.Debug().
		Str("key", sym.ExportHex()).
		Msg("Generated symmetric key")

	return sym.ExportHex()
}

func (a *authorizationService) ValidateToken(token []byte) bool {
	a.log.Trace().Str("token", string(token)).Msg("Validating token")
	return true
}
