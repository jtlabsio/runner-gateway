package routers

import (
	"fmt"
	"net/http"
	"strings"

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
		in := string(ctx.URI().Path())
		for pth := range pths {
			if strings.HasPrefix(in, pth) {
				pths[pth](ctx)
				return
			}
		}

		// handle the multiple scenarios (multiple runners)
		log.Warn().Str("path", in).Msg("No handler found for path")
		ctx.SetStatusCode(http.StatusNotFound)
		ctx.SetBodyString("Not Found")
	}, nil
}
