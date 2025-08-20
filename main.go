package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	nethttp "net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/firefart/entra-phishing-detection/internal/server"
	"github.com/goforj/godump"

	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/natefinch/lumberjack.v2"
)

type cliOptions struct {
	debugMode bool
}

func main() {
	var version bool
	var configCheckMode bool
	var configFilename string
	cli := cliOptions{}
	flag.BoolVar(&cli.debugMode, "debug", false, "Enable DEBUG mode")
	flag.StringVar(&configFilename, "config", "", "config file to use")
	flag.BoolVar(&configCheckMode, "configcheck", false, "just check the config")
	flag.BoolVar(&version, "version", false, "show version")
	flag.Parse()

	if version {
		buildInfo, ok := debug.ReadBuildInfo()
		if !ok {
			log.Fatalln("Unable to determine version information")
		}
		log.Printf("Version Information:\n%s", buildInfo)
		os.Exit(0)
	}

	configuration, err := config.GetConfig(configFilename)
	if err != nil {
		// check if we have a multierror from multiple validation errors
		var merr *multierror.Error
		if errors.As(err, &merr) {
			for _, e := range merr.Errors {
				log.Println("Error in config:", e.Error())
			}
			os.Exit(1)
		}
		// a normal error
		log.Fatalln("Error in config:", err.Error())
	}

	if cli.debugMode {
		godump.Dump(configuration)
	}

	// if we are in config check mode, we just validate the config and exit
	// if the config has errors, the statements above will already exit with an error
	if configCheckMode {
		return
	}

	var logger *slog.Logger
	if configuration.Logging.LogFile != "" {
		// Create parent directory if it doesn't exist
		if err := os.MkdirAll(filepath.Dir(configuration.Logging.LogFile), 0o755); err != nil {
			log.Fatalf("Error creating log directory: %v\n", err)
		}

		logFile, err := os.OpenFile(configuration.Logging.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
		if err != nil {
			log.Fatalf("Error opening log file: %v\n", err)
		}
		defer logFile.Close()

		var writer io.Writer
		if configuration.Logging.Rotate.Enabled {
			logRotator := &lumberjack.Logger{
				Filename: configuration.Logging.LogFile,
			}
			if configuration.Logging.Rotate.MaxSize > 0 {
				logRotator.MaxSize = configuration.Logging.Rotate.MaxSize
			}
			if configuration.Logging.Rotate.MaxBackups > 0 {
				logRotator.MaxBackups = configuration.Logging.Rotate.MaxBackups
			}
			if configuration.Logging.Rotate.MaxAge > 0 {
				logRotator.MaxAge = configuration.Logging.Rotate.MaxAge
			}
			if configuration.Logging.Rotate.Compress {
				logRotator.Compress = configuration.Logging.Rotate.Compress
			}
			writer = logRotator
		} else {
			writer = logFile
		}
		logger = newLogger(cli.debugMode, configuration.Logging.JSON, writer)
	} else {
		logger = newLogger(cli.debugMode, configuration.Logging.JSON, nil)
	}

	ctx := context.Background()
	err = run(ctx, logger, configuration, cli)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1) // nolint: gocritic
	}
}

func run(ctx context.Context, logger *slog.Logger, configuration config.Configuration, cliOptions cliOptions) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	reg := prometheus.NewRegistry()
	var metricOpts []metrics.OptionsMetricsFunc
	if configuration.Logging.AccessLog {
		metricOpts = append(metricOpts, metrics.WithAccessLog())
	}

	m, err := metrics.NewMetrics(reg, metricOpts...)
	if err != nil {
		return fmt.Errorf("failed to create metrics: %w", err)
	}

	options := []server.OptionsServerFunc{
		server.WithLogger(logger),
		server.WithConfig(configuration),
		server.WithDebug(cliOptions.debugMode),
		server.WithMetrics(m),
		server.WithCustomImages(configuration.Images),
	}

	if configuration.Logging.AccessLog {
		options = append(options, server.WithAccessLog())
	}

	s, err := server.NewServer(options...)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	srv := &nethttp.Server{
		Addr:         configuration.Server.Listen,
		Handler:      s,
		ReadTimeout:  configuration.Timeout,
		WriteTimeout: configuration.Timeout,
	}

	go func() {
		logger.Info("Starting server",
			slog.String("host", configuration.Server.Listen),
			slog.Duration("gracefultimeout", configuration.Server.GracefulTimeout),
			slog.Duration("timeout", configuration.Timeout),
			slog.Bool("debug", cliOptions.debugMode),
		)

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
			logger.Error("error on listenandserve", slog.String("err", err.Error()))
			// emit signal to kill server
			cancel()
		}
	}()

	var srvMetrics *nethttp.Server
	if configuration.Server.ListenMetrics != "" {
		muxMetrics := nethttp.NewServeMux()
		muxMetrics.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
		srvMetrics = &nethttp.Server{
			Addr:         configuration.Server.ListenMetrics,
			Handler:      muxMetrics,
			ReadTimeout:  configuration.Timeout,
			WriteTimeout: configuration.Timeout,
		}

		go func() {
			logger.Info("Starting metrics server",
				slog.String("host", configuration.Server.ListenMetrics),
			)
			if err := srvMetrics.ListenAndServe(); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
				logger.Error("error on metrics listenandserve", slog.String("err", err.Error()))
				// emit signal to kill server
				cancel()
			}
		}()
	}

	var srvPprof *nethttp.Server
	if configuration.Server.ListenPprof != "" {
		muxPprof := nethttp.NewServeMux()
		// copied from https://go.dev/src/net/http/pprof/pprof.go
		muxPprof.HandleFunc("GET /debug/pprof/", pprof.Index)
		muxPprof.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		muxPprof.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		muxPprof.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		muxPprof.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
		srvPprof = &nethttp.Server{
			Addr:    configuration.Server.ListenPprof,
			Handler: muxPprof,
			// higher timeout for pprof
			ReadTimeout:  2 * time.Minute,
			WriteTimeout: 2 * time.Minute,
		}

		go func() {
			logger.Info("Starting pprof server",
				slog.String("host", configuration.Server.ListenPprof),
			)
			if err := srvPprof.ListenAndServe(); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
				logger.Error("error on pprof listenandserve", slog.String("err", err.Error()))
				// emit signal to kill server
				cancel()
			}
		}()
	}

	// wait for a signal
	<-ctx.Done()
	logger.Info("received shutdown signal")
	// create a new context for shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), configuration.Server.GracefulTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("error on srv shutdown", slog.String("err", err.Error()))
	}
	if srvMetrics != nil {
		if err := srvMetrics.Shutdown(shutdownCtx); err != nil {
			logger.Error("error on metrics srv shutdown", slog.String("err", err.Error()))
		}
	}
	if srvPprof != nil {
		if err := srvPprof.Shutdown(shutdownCtx); err != nil {
			logger.Error("error on pprof srv shutdown", slog.String("err", err.Error()))
		}
	}
	return nil
}
