package main

import (
	"crypto/tls"
	"net"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
	"go.jtlabs.io/runner-gateway/internal/interfaces"
	"go.jtlabs.io/runner-gateway/internal/models"
	"go.jtlabs.io/runner-gateway/internal/routers"
	"go.jtlabs.io/runner-gateway/internal/services"
)

func main() {
	// load settings
	s, err := models.LoadSettings()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load settings")
	}

	var pstp interfaces.PASETOProvider

	// create a v4 service...
	if s.PASETO.Version == "v4" {
		v4p, err := services.NewV4Service(s)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create v4 PASETO service")
		}

		pstp = v4p
	}

	// create a v2 service...
	if s.PASETO.Version == "v2" {
		v2p, err := services.NewV2Service(s)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create v4 PASETO service")
		}

		pstp = v2p
	}

	// ensure we have a PASETO provider configured
	if pstp == nil {
		log.Fatal().Msg("Failed to create PASETO provider... please verify your configuration (only v2 and v4 are supported).")
	}

	// create the auth service with configured PASETO provider
	authSvc := services.NewAuthorizationService(pstp, s)

	// create gateway service
	gtwySvc := services.NewGatewayService(s)

	// register routes
	hndlr, err := routers.Register(s, authSvc, gtwySvc)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to register routes")
	}

	// start server
	log.Info().
		Str("address", s.Server.Address).
		Msg("Starting server...")

	if s.Server.CertificatePath == "" {
		// start HTTP server
		if err := fasthttp.ListenAndServe(s.Server.Address, hndlr); err != nil {
			log.Fatal().Err(err).Msg("Failed to start HTTP server")
		}

		return
	}

	// load tls configuration
	tlsSvc := services.NewTLSService(s)
	tlsCfg, err := tlsSvc.Configuration()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load TLS configuration")
	}

	// create a TCP listener on the specified port
	lstnr, err := net.Listen("tcp", s.Server.Address)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to listen on address")
	}
	defer lstnr.Close()

	// create a TLS listener on top of the TCP listener
	tlsLstnr := tls.NewListener(lstnr, tlsCfg)
	defer tlsLstnr.Close()

	// create a fasthttp server with the registered routes
	svr := &fasthttp.Server{
		Handler:               hndlr,
		NoDefaultServerHeader: true,
		ReadTimeout:           s.Server.ReadTimeout,
		WriteTimeout:          s.Server.WriteTimeout,
	}

	// start the server on the TLS listener
	if err := svr.Serve(tlsLstnr); err != nil {
		if strings.Contains(err.Error(), "use of closed network connection") {
			log.Info().Msg("Server shutting down gracefully")
			return
		}

		log.Fatal().Err(err).Msg("Failed to serve")
	}
}
