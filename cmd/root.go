package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "sakebomb",
	Short: "A Service Account Key generator",
	Long: `SAKeBomb is a CLI utility that creates short-lived Service Account Keys`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init()  {
	log.SetFormatter(&log.JSONFormatter{})
	if os.Getenv("SAB_DEBUG") == "TRUE" {
		log.SetLevel(log.DebugLevel)
	}
}