package routers

import (
	"fmt"
	"slices"

	"github.com/fasthttp/router"
	"github.com/rs/zerolog/log"
	"go.jtlabs.io/runner-gateway/internal/interfaces"
	"go.jtlabs.io/runner-gateway/internal/models"
)

func Register(s *models.Settings, as interfaces.AuthorizationService, gs interfaces.GatewayService) (*router.Router, error) {
	rtr := router.New()

	log.Trace().
		Str("package", "routers").
		Int("models", len(s.Runners)).
		Msg("Registering routes")

	pths := []string{}
	for _, rnr := range s.Runners {
		if slices.Contains(pths, rnr.Path) {
			return nil, fmt.Errorf("duplicate runner path detected in settings: %s (runner: %s)", rnr.Path, rnr.Name)
		}

		// track the paths we've registered to avoid duplicates
		pths = append(pths, rnr.Path)

		log.Debug().
			Str("host", rnr.Host).
			Str("path", rnr.Path).
			Str("scheme", rnr.Scheme).
			Msgf("Registering handler for model %s", rnr.Name)

		hndlr := gs.ForwardRequest(rnr.Host, rnr.Path, rnr.Scheme)
		rtr.ANY(rnr.Path, as.AuthorizeRequest(hndlr))
	}

	return rtr, nil
}
