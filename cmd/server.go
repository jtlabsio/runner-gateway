package main

import (
	"crypto/tls"
	"net"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
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

	// create authorization service
	authSvc := services.NewAuthorizationService(s)

	// create gateway service
	gtwySvc := services.NewGatewayService(s)

	// register routes
	rtr, err := routers.Register(s, authSvc, gtwySvc)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to register routes")
	}

	// start server
	log.Info().
		Interface("routes", rtr.List()).
		Str("address", s.Server.Address).
		Msg("Starting server...")

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
		Handler:               rtr.Handler,
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
