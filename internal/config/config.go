package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"

	"github.com/go-playground/validator/v10"
)

type Configuration struct {
	Server                        Server        `koanf:"server"`
	Logging                       Logging       `koanf:"logging"`
	Timeout                       time.Duration `koanf:"timeout" validate:"required"`
	Images                        Images        `koanf:"images"`
	AllowedOrigins                []string      `koanf:"allowed_origins" validate:"required,dive,fqdn"`
	TreatMissingRefererAsPhishing bool          `koanf:"treat_missing_referer_as_phishing"`
}

type Images struct {
	OK       map[string]string `koanf:"ok"`
	Phishing map[string]string `koanf:"phishing"`
}

type Server struct {
	Listen               string        `koanf:"listen" validate:"required,hostname_port"`
	ListenMetrics        string        `koanf:"listen_metrics" validate:"omitempty,hostname_port"`
	ListenPprof          string        `koanf:"listen_pprof" validate:"omitempty,hostname_port"`
	GracefulTimeout      time.Duration `koanf:"graceful_timeout" validate:"required"`
	SecretKeyHeaderName  string        `koanf:"secret_key_header_name" validate:"required"`
	SecretKeyHeaderValue string        `koanf:"secret_key_header_value" validate:"required"`
	IPHeader             string        `koanf:"ip_header"`
	HostHeaders          []string      `koanf:"host_headers"`
	PathImage            string        `koanf:"path_image"`
	PathHealth           string        `koanf:"path_health"`
	PathVersion          string        `koanf:"path_version"`
}

type Logging struct {
	AccessLog bool   `koanf:"access_log"`
	JSON      bool   `koanf:"json"`
	LogFile   string `koanf:"log_file" validate:"omitempty,filepath"`
	Rotate    struct {
		Enabled    bool `koanf:"enabled"`
		MaxSize    int  `koanf:"max_size" validate:"omitempty,gte=1"`
		MaxBackups int  `koanf:"max_backups" validate:"omitempty,gte=1"`
		MaxAge     int  `koanf:"max_age" validate:"omitempty,gte=1"`
		Compress   bool `koanf:"compress"`
	} `koanf:"rotate"`
}

var defaultConfig = Configuration{
	Server: Server{
		Listen:              "127.0.0.1:8000",
		GracefulTimeout:     10 * time.Second,
		SecretKeyHeaderName: "X-Secret-Key-Header",
	},
	AllowedOrigins:                []string{"login.microsoftonline.com", "login.microsoft.com", "autologon.microsoftazuread-sso.com", "device.login.microsoftonline.com"},
	TreatMissingRefererAsPhishing: true,
	Timeout:                       5 * time.Second,
}

// GetConfig loads the configuration from the specified file and environment variables.
// if the filename is empty, only the default configuration and environment variables are used.
func GetConfig(f string) (Configuration, error) {
	validate := validator.New(validator.WithRequiredStructEnabled())

	k := koanf.NewWithConf(koanf.Conf{
		Delim: ".",
	})

	if err := k.Load(structs.Provider(defaultConfig, "koanf"), nil); err != nil {
		return Configuration{}, err
	}

	// only load the json provider if a file is specified
	if f != "" {
		if err := k.Load(file.Provider(f), json.Parser()); err != nil {
			return Configuration{}, err
		}
	}

	if err := k.Load(env.Provider("ENTRA_", ".", func(s string) string {
		// hack so we can use double underscores in environment variables
		// we first replace all underscores with dots, and two dots represent
		// a former double underscore, so make this a normal underscore again
		// this allows for camel case environment variables
		s = strings.TrimPrefix(s, "ENTRA_")
		s = strings.ToLower(s)
		s = strings.ReplaceAll(s, "_", ".")
		s = strings.ReplaceAll(s, "..", "_")
		return s
	}), nil); err != nil {
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

	if len(config.Images.OK) > 0 {
		// ensure that the image names are lowercase
		for k, v := range config.Images.OK {
			if strings.Contains(k, "-") {
				return Configuration{}, fmt.Errorf("ok image name %q contains a dash, please only use the primary language", k)
			}
			lowerK := strings.ToLower(k)
			if lowerK != k {
				config.Images.OK[lowerK] = v
				delete(config.Images.OK, k)
			}
		}
		if _, ok := config.Images.OK["en"]; !ok {
			return Configuration{}, errors.New("ok image 'en' is required, please add it to the images map")
		}
	}

	if len(config.Images.Phishing) > 0 {
		for k, v := range config.Images.Phishing {
			if strings.Contains(k, "-") {
				return Configuration{}, fmt.Errorf("phishing image name %q contains a dash, please only use the primary language", k)
			}
			lowerK := strings.ToLower(k)
			if lowerK != k {
				config.Images.Phishing[lowerK] = v
				delete(config.Images.Phishing, k)
			}
		}

		if _, ok := config.Images.Phishing["en"]; !ok {
			return Configuration{}, errors.New("phishing image 'en' is required, please add it to the images map")
		}
	}

	return config, nil
}
