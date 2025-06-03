package routers

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
	"go.jtlabs.io/runner-gateway/internal/interfaces"
	"go.jtlabs.io/runner-gateway/internal/models"
)

func Register(s *models.Settings, as interfaces.AuthorizationService, gs interfaces.GatewayService) (fasthttp.RequestHandler, error) {
	log.Trace().
		Str("package", "routers").
		Int("models", len(s.Runners)).
		Msg("Registering routes")

	pths := map[string]fasthttp.RequestHandler{}
	for _, rnr := range s.Runners {
		if _, ok := pths[rnr.Path]; ok {
			return nil, fmt.Errorf("duplicate runner path detected in settings: %s (runner: %s)", rnr.Path, rnr.Name)
		}

		log.Debug().
			Str("host", rnr.Host).
			Str("path", rnr.Path).
			Str("scheme", rnr.Scheme).
			Msgf("Registering handler for model %s", rnr.Name)

		pths[rnr.Path] = as.AuthorizeRequest(gs.ForwardRequest(rnr.Host, rnr.Path, rnr.Scheme))
	}

	return func(ctx *fasthttp.RequestCtx) {
		// handle the default scenario (1 runner)
		if len(pths) == 1 {
			pths[s.Runners[0].Path](ctx)
			return
		}

		// handle the multiple scenarios (multiple runners)
		// TODO: implement routing logic for multiple runners
		log.Fatal().Msg("Multiple runners not yet implemented")
		ctx.SetStatusCode(http.StatusNotFound)
		ctx.SetBodyString("Not Found")
	}, nil
}
