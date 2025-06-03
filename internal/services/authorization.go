package services

import (
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
	"go.jtlabs.io/runner-gateway/internal/interfaces"
	"go.jtlabs.io/runner-gateway/internal/models"
)

type authorizationService struct {
	pp  interfaces.PASETOProvider
	log zerolog.Logger
	s   *models.Settings
}

func NewAuthorizationService(pp interfaces.PASETOProvider, s *models.Settings) *authorizationService {
	svc := &authorizationService{
		pp:  pp,
		log: log.With().Str("service", "gateway").Logger(),
		s:   s,
	}

	return svc
}

func (svc *authorizationService) AuthorizeRequest(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		svc.log.Trace().
			Str("uri", string(ctx.RequestURI())).
			Msg("Authorizing request")

		// validate Authorization
		hdr := ctx.Request.Header.Peek("Authorization")
		if hdr == nil {
			ctx.Error("Missing authorization error", fasthttp.StatusUnauthorized)
			return
		}

		// trim the prefix "Bearer " from the header value
		tkn := strings.TrimPrefix(string(hdr), "Bearer ")

		// validate token
		if err := svc.ValidateToken(tkn); err != nil {
			ctx.Error(err.Error(), fasthttp.StatusUnauthorized)
			return
		}

		next(ctx)
	}
}

func (svc *authorizationService) GenerateAsymmetricKeyPair() (string, string, error) {
	svc.log.Trace().Msg("Generating asymmetric key pair")
	pub, key, err := svc.pp.GenerateAsymmetricKeyPair()
	if err != nil {
		return "", "", err
	}

	svc.log.Debug().
		Str("public", pub).
		Msg("Generated asymmetric key pair")

	return pub, key, nil
}

func (svc *authorizationService) GeneratePrivatePASETO() (string, error) {
	svc.log.Trace().Msg("Generating PASETO token")

	tkn := newToken(svc.s.PASETO.Expiration)
	enc, err := svc.pp.EncryptToken(tkn)
	if err != nil {
		return "", err
	}

	svc.log.Debug().
		Str("paseto", enc).
		Msg("Generated private PASETO token")

	return enc, nil
}

func (svc *authorizationService) GeneratePublicPASETO() (string, error) {
	svc.log.Trace().Msg("Generating PASETO token")

	// generate and sign the new token
	tkn := newToken(svc.s.PASETO.Expiration)
	sgn, err := svc.pp.SignToken(tkn)
	if err != nil {
		return "", err
	}

	svc.log.Debug().
		Str("paseto", sgn).
		Msg("Generated public PASETO token")

	return sgn, nil
}

func (svc *authorizationService) GenerateSymmetricKey() string {
	svc.log.Trace().Msg("Generating symmetric key")
	sym := svc.pp.GenerateSymmetricKey()

	svc.log.Debug().
		Str("key", sym).
		Msg("Generated symmetric key")

	return sym
}

func (svc *authorizationService) ValidateToken(tkn string) error {
	svc.log.Trace().Str("token", tkn).Msg("Validating token")

	if err := svc.pp.ValidateToken(tkn); err != nil {
		svc.log.Warn().
			Err(err).
			Str("token", tkn).
			Msg("Failed to parse token")
		return err
	}

	return nil
}
