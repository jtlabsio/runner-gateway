package models

import (
	"time"

	"github.com/rs/zerolog"
	"go.jtlabs.io/settings"
)

type Settings struct {
	Logging struct {
		Level string `json:"level" yaml:"level"`
	} `json:"logging" yaml:"logging"`
	PASETO struct {
		Expiration time.Duration `json:"expiration" yaml:"expiration"`
		KeyPath    string        `json:"keyPath" yaml:"keyPath"`
		PublicPath string        `json:"publicPath" yaml:"publicPath"`
		SecretKey  string        `json:"secretKey" yaml:"secretKey"`
		Version    string        `json:"version" yaml:"version"`
	} `json:"paseto" yaml:"paseto"`
	Runners []struct {
		Host   string `json:"host" yaml:"host"`
		Name   string `json:"name" yaml:"name"`
		Path   string `json:"path" yaml:"path"`
		Scheme string `json:"scheme" yaml:"scheme"`
	} `json:"runners" yaml:"runners"`
	Server struct {
		Address         string        `json:"address" yaml:"address"`
		CertificatePath string        `json:"certificatePath" yaml:"certificatePath"`
		KeyPath         string        `json:"keyPath" yaml:"keyPath"`
		ReadTimeout     time.Duration `json:"readTimeoutSeconds" yaml:"readTimeoutSeconds"`
		WriteTimeout    time.Duration `json:"writeTimeoutSeconds" yaml:"writeTimeoutSeconds"`
	} `json:"server" yaml:"server"`
}

func (s *Settings) globalLogLevel() zerolog.Level {
	switch s.Logging.Level {
	case "trace":
		return zerolog.TraceLevel
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

func LoadSettings() (*Settings, error) {
	s := &Settings{}

	// configure settings options
	opts := settings.Options().
		SetArgsMap(map[string]string{
			"--logging-level": "Logging.Level",
		}).
		SetBasePath("./settings/settings.yaml").
		SetEnvOverride("ENV", "GO_ENV").
		SetEnvSearchPaths("./settings").
		SetVarsMap(map[string]string{
			"LOGGING_LEVEL":           "Logging.Level",
			"OLLAMA_HOST":             "Ollama.Host",
			"PASETO_SECRET_KEY":       "Paseto.SecretKey",
			"SERVER_ADDRESS":          "Server.Address",
			"SERVER_CERTIFICATE_PATH": "Server.CertificatePath",
			"SERVER_KEY_PATH":         "Server.KeyPath",
		})

	// read settings from file and environment variables
	if err := settings.Gather(opts, s); err != nil {
		return nil, err
	}

	// set global log level
	zerolog.SetGlobalLevel(s.globalLogLevel())

	return s, nil
}
