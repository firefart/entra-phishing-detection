package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	nethttp "net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/firefart/entra-phishing-detection/internal/server"

	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/automaxprocs/maxprocs"
)

func main() {
	if _, err := maxprocs.Set(); err != nil {
		panic(fmt.Sprintf("Error on gomaxprocs: %v\n", err))
	}

	var debugMode bool
	var configFilename string
	var jsonOutput bool
	var version bool
	var configCheckMode bool
	var listen string
	var listenMetrics string
	flag.BoolVar(&debugMode, "debug", false, "Enable DEBUG mode")
	flag.StringVar(&listen, "listen", "127.0.0.1:8000", "listen address")
	flag.StringVar(&listenMetrics, "listen-metrics", "127.0.0.1:8001", "listen address")
	flag.StringVar(&configFilename, "config", "", "config file to use")
	flag.BoolVar(&jsonOutput, "json", false, "output in json instead")
	flag.BoolVar(&configCheckMode, "configcheck", false, "just check the config")
	flag.BoolVar(&version, "version", false, "show version")
	flag.Parse()

	if version {
		buildInfo, ok := debug.ReadBuildInfo()
		if !ok {
			fmt.Println("Unable to determine version information") // nolint: forbidigo
			os.Exit(1)
		}
		fmt.Printf("%s", buildInfo) // nolint: forbidigo
		os.Exit(0)
	}

	logger := newLogger(debugMode, jsonOutput)
	ctx := context.Background()
	var err error
	if configCheckMode {
		err = configCheck(configFilename)
	} else {
		err = run(ctx, logger, configFilename, debugMode, listen, listenMetrics)
	}

	if err != nil {
		// check if we have a multierror
		var merr *multierror.Error
		if errors.As(err, &merr) {
			for _, e := range merr.Errors {
				logger.Error(e.Error())
			}
			os.Exit(1)
		}
		// a normal error
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func configCheck(configFilename string) error {
	_, err := config.GetConfig(configFilename)
	return err
}

func run(ctx context.Context, logger *slog.Logger, configFilename string, debugMode bool, listen string, listenMetrics string) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if configFilename == "" {
		return errors.New("please provide a config file")
	}

	configuration, err := config.GetConfig(configFilename)
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	if err != nil {
		return fmt.Errorf("failed to create metrics: %w", err)
	}

	options := []server.OptionsServerFunc{
		server.WithLogger(logger),
		server.WithConfig(configuration),
		server.WithDebug(debugMode),
		server.WithMetrics(m),
	}

	s := server.NewServer(options...)

	srv := &nethttp.Server{
		Addr:         listen,
		Handler:      s,
		ReadTimeout:  configuration.Timeout,
		WriteTimeout: configuration.Timeout,
	}

	go func() {
		logger.Info("Starting server",
			slog.String("host", listen),
			slog.Duration("gracefultimeout", configuration.Server.GracefulTimeout),
			slog.Duration("timeout", configuration.Timeout),
			slog.Bool("debug", debugMode),
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
		Addr:         listenMetrics,
		Handler:      muxMetrics,
		ReadTimeout:  configuration.Timeout,
		WriteTimeout: configuration.Timeout,
	}

	go func() {
		logger.Info("Starting metrics server",
			slog.String("host", listenMetrics),
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
