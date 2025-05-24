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

type cliOptions struct {
	debugMode      bool
	configFilename string
	accessLog      bool
	listen         string
	listenMetrics  string
}

func main() {
	if _, err := maxprocs.Set(); err != nil {
		panic(fmt.Sprintf("Error on gomaxprocs: %v\n", err))
	}

	var version bool
	var configCheckMode bool
	var jsonOutput bool
	var logFileName string
	cli := cliOptions{}
	flag.BoolVar(&cli.debugMode, "debug", false, "Enable DEBUG mode")
	flag.StringVar(&cli.listen, "listen", "127.0.0.1:8000", "listen address")
	flag.StringVar(&cli.listenMetrics, "listen-metrics", "127.0.0.1:8001", "listen address")
	flag.StringVar(&cli.configFilename, "config", "", "config file to use")
	flag.BoolVar(&cli.accessLog, "access-log", false, "turn on access logging if no reverse proxy is used")
	flag.BoolVar(&jsonOutput, "json", false, "output in json instead")
	flag.StringVar(&logFileName, "logfile", "", "also log to log file (and to stdout)")
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

	var logger *slog.Logger
	var err error
	if logFileName != "" {
		logFile, err := os.OpenFile(logFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
		if err != nil {
			fmt.Printf("Error opening log file: %v\n", err) // nolint: forbidigo
			os.Exit(1)
		}
		defer logFile.Close()

		logger = newLogger(cli.debugMode, jsonOutput, logFile)
	} else {
		logger = newLogger(cli.debugMode, jsonOutput, nil)
	}

	ctx := context.Background()
	if configCheckMode {
		err = configCheck(cli.configFilename)
	} else {
		err = run(ctx, logger, cli)
	}

	if err != nil {
		// check if we have a multierror
		var merr *multierror.Error
		if errors.As(err, &merr) {
			for _, e := range merr.Errors {
				logger.Error(e.Error())
			}
			os.Exit(1) // nolint: gocritic
		}
		// a normal error
		logger.Error(err.Error())
		os.Exit(1) // nolint: gocritic
	}
}

func configCheck(configFilename string) error {
	_, err := config.GetConfig(configFilename)
	return err
}

func run(ctx context.Context, logger *slog.Logger, cliOptions cliOptions) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if cliOptions.configFilename == "" {
		return errors.New("please provide a config file")
	}

	configuration, err := config.GetConfig(cliOptions.configFilename)
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
		server.WithDebug(cliOptions.debugMode),
		server.WithMetrics(m),
	}

	if cliOptions.accessLog {
		options = append(options, server.WithAccessLog())
	}

	s := server.NewServer(options...)

	srv := &nethttp.Server{
		Addr:         cliOptions.listen,
		Handler:      s,
		ReadTimeout:  configuration.Timeout,
		WriteTimeout: configuration.Timeout,
	}

	go func() {
		logger.Info("Starting server",
			slog.String("host", cliOptions.listen),
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
		Addr:         cliOptions.listenMetrics,
		Handler:      muxMetrics,
		ReadTimeout:  configuration.Timeout,
		WriteTimeout: configuration.Timeout,
	}

	go func() {
		logger.Info("Starting metrics server",
			slog.String("host", cliOptions.listenMetrics),
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
