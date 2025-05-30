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

func (svc *tlsService) Configuration() (*tls.Config, error) {
	svc.log.Trace().Msg("Creating TLS configuration")
	crt, err := svc.LoadCertificate()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			crt,
		},
	}, nil
}

func (svc *tlsService) LoadCertificate() (tls.Certificate, error) {
	svc.log.Trace().
		Str("certPath", svc.s.Server.CertificatePath).
		Str("keyPath", svc.s.Server.KeyPath).
		Msg("Loading TLS certificate")

	crt, err := tls.LoadX509KeyPair(svc.s.Server.CertificatePath, svc.s.Server.KeyPath)
	if err != nil {
		return crt, err
	}

	return crt, nil
}
