package services

import (
	"errors"
	"os"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
	"go.jtlabs.io/runner-gateway/internal/models"
)

type authorizationService struct {
	pk  paseto.V4AsymmetricPublicKey
	log zerolog.Logger
	s   *models.Settings
	sk  paseto.V4SymmetricKey
}

func (svc *authorizationService) newToken() paseto.Token {
	n := time.Now()

	// generate a new token
	tkn := paseto.NewToken()
	tkn.SetIssuedAt(n)
	tkn.SetNotBefore(n)
	tkn.SetExpiration(n.Add(svc.s.PASETO.Expiration))

	return tkn
}

func (svc *authorizationService) readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func NewAuthorizationService(s *models.Settings) *authorizationService {
	svc := &authorizationService{
		log: log.With().Str("service", "gateway").Logger(),
		s:   s,
	}

	// load public key from configuration
	sk, err := paseto.V4SymmetricKeyFromHex(s.PASETO.SecretKey)
	if err != nil {
		svc.log.Warn().Err(err).Msg("Failed to create symmetric key from hex")
	}

	// assign symmetric key to service variable if no error occurred
	if err == nil {
		svc.sk = sk
	}

	// load public key from file
	key, err := svc.readFile(s.PASETO.PublicPath)
	if err != nil {
		svc.log.Warn().
			Err(err).
			Str("path", s.PASETO.PublicPath).
			Msg("Failed to read secret key file")

		return svc
	}

	// create public key from hex string
	pk, err := paseto.NewV4AsymmetricPublicKeyFromHex(key)
	if err != nil {
		svc.log.Error().Err(err).Msg("Failed to create secret key from hex")

		return svc
	}

	// assign public key to service variable if no error occurred
	svc.pk = pk

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

func (svc *authorizationService) GenerateAsymmetricKeyPair() (string, string) {
	svc.log.Trace().Msg("Generating asymmetric key pair")
	asym := paseto.NewV4AsymmetricSecretKey()

	svc.log.Debug().
		Str("public", asym.Public().ExportHex()).
		Msg("Generated public PASETO token")

	return asym.ExportHex(), asym.Public().ExportHex()
}

func (svc *authorizationService) GeneratePrivatePASETO() (string, error) {
	svc.log.Trace().Msg("Generating PASETO token")

	tkn := svc.newToken()
	enc := tkn.V4Encrypt(svc.sk, nil)

	svc.log.Debug().
		Str("paseto", enc).
		Msg("Generated private PASETO token")

	return enc, nil
}

func (svc *authorizationService) GeneratePublicPASETO() (string, error) {
	svc.log.Trace().Msg("Generating PASETO token")

	// load public key from file
	prv, err := svc.readFile(svc.s.PASETO.KeyPath)
	if err != nil {
		svc.log.Warn().Err(err).Msg("Failed to read secret key file")
		return "", err
	}

	ak, err := paseto.NewV4AsymmetricSecretKeyFromHex(prv)
	if err != nil {
		svc.log.Error().Err(err).Msg("Failed to create secret key from hex")
		return "", err
	}

	// generate and sign the new token
	tkn := svc.newToken()
	sgn := tkn.V4Sign(ak, nil)

	svc.log.Debug().
		Str("paseto", sgn).
		Msg("Generated public PASETO token")

	return sgn, nil
}

func (svc *authorizationService) GenerateSymmetricKey() string {
	svc.log.Trace().Msg("Generating symmetric key")
	sym := paseto.NewV4SymmetricKey()

	svc.log.Debug().
		Str("key", sym.ExportHex()).
		Msg("Generated symmetric key")

	return sym.ExportHex()
}

func (svc *authorizationService) ValidateToken(token string) error {
	svc.log.Trace().Str("token", token).Msg("Validating token")

	// check for v4.public
	if strings.HasPrefix(token, "v4.public.") {
		// validate public token
		prsr := paseto.NewParser()
		if _, err := prsr.ParseV4Public(svc.pk, token, nil); err != nil {
			svc.log.Warn().
				Err(err).
				Str("token", token).
				Msg("Failed to parse public token")
			return errors.New("v4.public tokens are not supported at this time")
		}

		return nil
	}

	// check for v4.private
	if strings.HasPrefix(token, "v4.local.") {
		// validate private token
		prsr := paseto.NewParser()
		if _, err := prsr.ParseV4Local(svc.sk, token, nil); err != nil {
			svc.log.Warn().
				Err(err).
				Str("token", token).
				Msg("Failed to parse private token")
			return errors.New("v4.private tokens are not supported at this time")
		}

		return nil
	}

	svc.log.Warn().Str("token", token).Msg("Unsupported token format provided")
	return errors.New("unsupported token format provided")
}
