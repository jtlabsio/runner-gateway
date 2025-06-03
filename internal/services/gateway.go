package services

import (
	"runtime/debug"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
	"go.jtlabs.io/runner-gateway/internal/models"
)

type gatewayService struct {
	log zerolog.Logger
	s   *models.Settings
}

type proxyRequest struct {
	rcvd time.Time
	req  *fasthttp.Request
}

func NewGatewayService(s *models.Settings) *gatewayService {
	return &gatewayService{
		log: log.With().Str("service", "gateway").Logger(),
		s:   s,
	}
}

func (svc *gatewayService) ForwardRequest(hst string, pthPfx string, schm string) func(*fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		pxyReq := &proxyRequest{
			rcvd: time.Now(),
			req:  fasthttp.AcquireRequest(),
		}

		// recovery for unhandled exceptions
		defer func() {
			if rec := recover(); rec != nil {
				switch val := rec.(type) {
				case error:
					ctx.SetStatusCode(fasthttp.StatusInternalServerError)
					ctx.SetBodyString(val.Error())
				default:
					ctx.SetStatusCode(fasthttp.StatusInternalServerError)
					ctx.SetBodyString("Internal server error")
				}

				svc.log.Error().
					Str("duration", time.Since(pxyReq.rcvd).String()).
					Interface("panic", rec).
					Str("stacktrace", string(debug.Stack())).
					Msg("Recovered from panic")
			}
		}()

		// copy the inbound request to the proxy request state struct
		ctx.Request.CopyTo(pxyReq.req)

		// evaluate inbound path and determine if adjustments are needed
		dwnUri := pxyReq.req.URI()
		pth := string(dwnUri.Path())
		if len(pthPfx) > 1 {
			svc.log.Trace().
				Str("prefix", pthPfx).
				Str("path", pth).
				Msg("Trimming prefix from path")
			pth = strings.TrimPrefix(pth, pthPfx)
		}

		// 
		svc.log.Debug().
			Str("originalHost", string(dwnUri.Host())).
			Str("originalPath", string(dwnUri.Path())).
			Str("originalScheme", string(dwnUri.Scheme())).
			Str("targetHost", hst).
			Str("targetPath", pth).
			Str("targetScheme", schm).
			Msg("Forwarding request")

		dwnUri.SetHost(hst)
		dwnUri.SetPath(pth)
		dwnUri.SetScheme(schm)

		// reverse proxy the request, log any errors and respond accordingly
		if err := fasthttp.Do(pxyReq.req, &ctx.Response); err != nil {
			svc.log.Error().
				Err(err).
				Str("uri", dwnUri.String()).
				Msg("Failed to proxy request")

			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(err.Error())
			return
		}

		svc.log.Info().
			Str("duration", time.Since(pxyReq.rcvd).String()).
			Str("originalHost", string(dwnUri.Host())).
			Str("originalPath", string(dwnUri.Path())).
			Str("originalScheme", string(dwnUri.Scheme())).
			Str("targetHost", hst).
			Str("targetPath", pth).
			Str("targetScheme", schm).
			Msg("Successfully proxied request")
	}
}
