package main

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type ACLConfiguration struct {
	CIDR          string `validate:"cidrv4,required"`
	InternalPorts string `validate:"range,required"`
	Deny          bool
}
type Configuration struct {
	ACLAllowDefault bool
	CreateChains    bool
	DataDir         string `validate:"dir,required"`
	ExternalIP      string `validate:"omitempty,ipv4"`
	ListenAddr      string `validate:"hostname_port,required"`
	LogFormat       string
	LogLevel        string
	PortRange       string `validate:"range,required"`
	SkipJumpCheck   bool
	ACL             []ACLConfiguration
}

func NewRootCommand() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use: "pcp-server",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
			return initializeConfig(cmd)
		},
		Run: func(cmd *cobra.Command, args []string) {
			start()
		},
	}
	rootCmd.PersistentFlags().StringP("config", "c", "config.yaml", "config file")
	rootCmd.PersistentFlags().StringP("data-dir", "d", "/tmp/pcp", "director to use for storing data")
	rootCmd.PersistentFlags().String("external-ip", "", "ip to report to client as external (default auto detect)")
	rootCmd.PersistentFlags().String("listen-addr", ":5351", "address to listen on for pcp requests")
	rootCmd.PersistentFlags().String("log-level", "INFO", "log level")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (plain/json)")
	rootCmd.Flags().Bool("create-chains", true, "create required chains")
	rootCmd.Flags().Bool("skip-jump-check", false, "disable check of rule pointing to chains")
	rootCmd.Flags().Bool("acl-allow-default", false, "default allow port mappings")
	rootCmd.Flags().String("port-range", "10000-19999", "external port range to allocate from")
	return rootCmd
}
func initializeConfig(cmd *cobra.Command) error {
	vp := viper.New()
	// Don't forget to read config either from cfgFile or from home directory!
	cfgFile, err := cmd.PersistentFlags().GetString("config")
	if err != nil {
		return err
	}

	if cfgFile != "" {
		if _, err := os.Stat(cfgFile); err == nil {
			// Use config file from the flag.
			vp.SetConfigFile(cfgFile)
			if err := vp.ReadInConfig(); err != nil {
				return err
			}
		}
	}

	vp.SetEnvPrefix("PCP")
	vp.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	vp.AutomaticEnv()

	bindFlags(cmd, vp)

	if err := vp.Unmarshal(&config); err != nil {
		return err
	}

	validate := validator.New()
	validate.RegisterValidation("range", func(fl validator.FieldLevel) bool {
		v := fl.Field().String()

		match, _ := regexp.MatchString("^[0-9]+-[0-9]+$", v)
		if !match {
			return false
		}

		split := strings.Split(v, "-")
		if len(split) != 2 {
			return false
		}

		start, _ := strconv.Atoi(split[0])
		end, _ := strconv.Atoi(split[1])

		if start < end && start > 0 && end <= math.MaxUint16 {
			return true
		}

		return false
	})
	if err := validate.Struct(&config); err != nil {
		return err
	}

	return nil
}

// Bind each cobra flag to its associated viper configuration (config file and environment variable)
func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// If using camelCase in the config file, replace hyphens with a camelCased string.
		// Since viper does case-insensitive comparisons, we don't need to bother fixing the case, and only need to remove the hyphens.
		configName := strings.ReplaceAll(f.Name, "-", "")

		v.RegisterAlias(strings.ReplaceAll(f.Name, "-", "_"), configName)

		v.BindEnv(configName, "PCP_"+strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_")))

		v.SetDefault(configName, f.DefValue)

		if f.Changed {
			v.Set(configName, f.Value)
		}
	})
}

func getLogger() *zap.Logger {
	level, err := zapcore.ParseLevel(config.LogLevel)
	if err != nil {
		fmt.Println("failed to parse level")
		os.Exit(1)
	}

	var zcore zapcore.Core

	if config.LogFormat == "plain" {
		zcore = zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(os.Stdout), level)
	} else {
		encoderConfig := ecszap.NewDefaultEncoderConfig()
		zcore = ecszap.NewCore(encoderConfig, os.Stdout, level)
	}

	return zap.New(zcore, zap.AddCaller())
}
