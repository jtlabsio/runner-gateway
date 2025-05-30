package services

import (
	"crypto/tls"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.jtlabs.io/runner-gateway/internal/models"
)

type tlsService struct {
	log zerolog.Logger
	s   *models.Settings
}

func NewTLSService(s *models.Settings) *tlsService {
	return &tlsService{
		log: log.With().Str("service", "tls").Logger(),
		s:   s,
	}
}

func (t *tlsService) Configuration() (*tls.Config, error) {
	t.log.Trace().Msg("Creating TLS configuration")
	crt, err := t.LoadCertificate()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			crt,
		},
	}, nil
}

func (t *tlsService) LoadCertificate() (tls.Certificate, error) {
	t.log.Trace().
		Str("certPath", t.s.Server.CertificatePath).
		Str("keyPath", t.s.Server.KeyPath).
		Msg("Loading TLS certificate")

	crt, err := tls.LoadX509KeyPair(t.s.Server.CertificatePath, t.s.Server.KeyPath)
	if err != nil {
		return crt, err
	}

	return crt, nil
}
