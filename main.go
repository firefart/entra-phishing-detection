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
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/firefart/entra-phishing-detection/internal/server"
	"github.com/goforj/godump"

	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/automaxprocs/maxprocs"
	"gopkg.in/natefinch/lumberjack.v2"
)

type cliOptions struct {
	debugMode bool
}

func main() {
	if _, err := maxprocs.Set(); err != nil {
		log.Fatalf("Error on gomaxprocs: %v\n", err)
	}

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

	muxMetrics := nethttp.NewServeMux()
	muxMetrics.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	srvMetrics := &nethttp.Server{
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

	// wait for a signal
	<-ctx.Done()
	logger.Info("received shutdown signal")
	// create a new context for shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), configuration.Server.GracefulTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("error on srv shutdown", slog.String("err", err.Error()))
	}
	if err := srvMetrics.Shutdown(shutdownCtx); err != nil {
		logger.Error("error on metrics srv shutdown", slog.String("err", err.Error()))
	}
	return nil
}
