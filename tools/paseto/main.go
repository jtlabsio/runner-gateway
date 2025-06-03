package main

import (
	"flag"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.jtlabs.io/runner-gateway/internal/interfaces"
	"go.jtlabs.io/runner-gateway/internal/models"
	"go.jtlabs.io/runner-gateway/internal/services"
)

const (
	keyPath = "./settings/paseto.key"
	pubPath = "./settings/paseto.pub"
)

func generateKeyPair(authSvc interfaces.AuthorizationService) {
	pub, crt, err := authSvc.GenerateAsymmetricKeyPair()
	if err != nil {
		log.Fatal().
			Err(err).
			Msg("Unable to generate key pair")
	}

	if err := writeFile(keyPath, os.O_CREATE|os.O_WRONLY, 0644, crt); err != nil {
		log.Fatal().
			Err(err).
			Str("path", keyPath).
			Msg("Unable to create private key")
	}

	if err := writeFile(pubPath, os.O_CREATE|os.O_WRONLY, 0644, pub); err != nil {
		log.Fatal().
			Err(err).
			Str("path", pubPath).
			Msg("Unable to create public key")
	}
}

func writeFile(pth string, flg int, prm os.FileMode, data string) error {
	f, err := os.OpenFile(pth, flg, prm)
	if err != nil {
		return err
	}
	defer f.Close()

	// convert to hexidecimal to store it
	if _, err := f.WriteString(data); err != nil {
		return err
	}

	return nil
}

func main() {
	// set zerolog writer to terminal
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})

	// load settings
	s, err := models.LoadSettings()
	if err != nil {
		log.Fatal().
			Err(err).
			Msg("Failed to load settings")
	}

	// initialize paseto service
	var pstp interfaces.PASETOProvider

	// create a v4 service
	if s.PASETO.Version == "v4" {
		v4p, err := services.NewV4Service(s)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create v4 PASETO service")
		}

		pstp = v4p
	}

	// create a v2 service
	if s.PASETO.Version == "v2" {
		v2p, err := services.NewV2Service(s)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create v4 PASETO service")
		}

		pstp = v2p
	}

	if pstp == nil {
		log.Fatal().Msg("Failed to create PASETO provider... please verify your configuration (only v2 and v4 are supported).")
	}

	// initialize authorization service
	authSvc := services.NewAuthorizationService(pstp, s)

	// read command line arguments
	actn := flag.String("action", "", "Action to perform (assymetric|public|private|symmetric|verify)")
	tkn := flag.String("token", "", "[Optional] Token to validate")
	flag.Parse()

	if actn == nil {
		log.Fatal().
			Msg("No action specified")
		return
	}

	switch *actn {
	case "asymmetric":
		// Generate a new PASETO key pair
		generateKeyPair(authSvc)
		log.Info().
			Str("certifatePath", keyPath).
			Str("publicPath", pubPath).
			Msg("Public private key pair generated successfully")

	case "public":
		// Generate a new PASETO token
		tkn, err := authSvc.GeneratePublicPASETO()
		if err != nil {
			log.Fatal().
				Err(err).
				Msg("Failed to generate public PASETO token")
		}

		log.Info().
			Str("token", tkn).
			Msg("Public PASETO token generated successfully")

	case "private":
		// Generate a new PASETO token
		tkn, err := authSvc.GeneratePrivatePASETO()
		if err != nil {
			log.Fatal().
				Err(err).
				Msg("Failed to generate private PASETO token")
		}

		log.Info().
			Str("token", tkn).
			Msg("Private PASETO token generated successfully")

	case "symmetric":
		// Generate symmetric key
		sym := authSvc.GenerateSymmetricKey()
		log.Info().
			Str("symmetricKey", sym).
			Msg("Symmetric key generated successfully")

	case "validate":
		// Validate a PASETO token
		if *tkn == "" {
			log.Fatal().
				Msg("No token provided for validation")
		}

		if err := authSvc.ValidateToken(*tkn); err != nil {
			log.Fatal().
				Err(err).
				Msg("Failed to validate PASETO token")
		}

		log.Info().
			Msg("PASETO token validated successfully")

	default:
		log.Fatal().
			Str("action", *actn).
			Msg("Invalid action specified")
	}
}
