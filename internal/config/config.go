package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"

	"github.com/go-playground/validator/v10"
)

type Configuration struct {
	Server         Server        `koanf:"server"`
	Timeout        time.Duration `koanf:"timeout" validate:"required"`
	AllowedOrigins []string      `koanf:"allowed_origins" validate:"required,dive,fqdn"`
}

type Server struct {
	GracefulTimeout      time.Duration `koanf:"graceful_timeout" validate:"required"`
	SecretKeyHeaderName  string        `koanf:"secret_key_header_name" validate:"required"`
	SecretKeyHeaderValue string        `koanf:"secret_key_header_value" validate:"required"`
	IPHeader             string        `koanf:"ip_header"`
	HostHeaders          []string      `koanf:"host_headers"`
	PathImage            string        `koanf:"path_image"`
	PathHealth           string        `koanf:"path_health"`
	PathVersion          string        `koanf:"path_version"`
}

var defaultConfig = Configuration{
	Server: Server{
		GracefulTimeout:     10 * time.Second,
		SecretKeyHeaderName: "X-Secret-Key-Header",
	},
	AllowedOrigins: []string{"login.microsoftonline.com"},
	Timeout:        5 * time.Second,
}

func GetConfig(f string) (Configuration, error) {
	validate := validator.New(validator.WithRequiredStructEnabled())

	k := koanf.NewWithConf(koanf.Conf{
		Delim: ".",
	})

	if err := k.Load(structs.Provider(defaultConfig, "koanf"), nil); err != nil {
		return Configuration{}, err
	}

	if err := k.Load(file.Provider(f), json.Parser()); err != nil {
		return Configuration{}, err
	}

	var config Configuration
	if err := k.Unmarshal("", &config); err != nil {
		return Configuration{}, err
	}

	if err := validate.Struct(config); err != nil {
		var invalidValidationError *validator.InvalidValidationError
		if errors.As(err, &invalidValidationError) {
			return Configuration{}, err
		}

		var valErr validator.ValidationErrors
		if ok := errors.As(err, &valErr); !ok {
			return Configuration{}, fmt.Errorf("could not cast err to ValidationErrors: %w", err)
		}
		var resultErr error
		for _, err := range valErr {
			resultErr = multierror.Append(resultErr, err)
		}
		return Configuration{}, resultErr
	}

	// cleanup config
	// remove leading slashes from paths
	config.Server.PathImage = strings.TrimLeft(config.Server.PathImage, "/")
	config.Server.PathHealth = strings.TrimLeft(config.Server.PathHealth, "/")
	config.Server.PathVersion = strings.TrimLeft(config.Server.PathVersion, "/")

	return config, nil
}
