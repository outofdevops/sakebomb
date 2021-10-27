package cmd

import (
	"bytes"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"sakebomb/certs"
	"strconv"
	"text/template"
)

const (
	expiryTimeFlag     = "expiry-time"
	publicKeyFileFlag  = "public-key-file"
	privateKeyFileFlag = "private-key-file"
	defaultExpiryTime        = 5
	defaultPublicKeyPEMFile  = "public.pem"
	defaultPrivateKeyPEMFile = "private.pem"
)

type GCParams struct {
	expiryTime     int
	publicKeyFile  string
	privateKeyFile string
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generates a Service Account's Public/Private Keys",
	Long: fmt.Sprintf("Generates a Service Account Key Pair and saves it in two files (default destinations %s " +
		"and %s), use --%s and --%s flags to change destinations",
		defaultPublicKeyPEMFile, defaultPrivateKeyPEMFile, publicKeyFileFlag, privateKeyFileFlag),
	RunE: func(cmd *cobra.Command, args []string) error {
		params, err := extractParams(cmd.Flag(expiryTimeFlag).Value.String(),
			cmd.Flag(publicKeyFileFlag).Value.String(),
			cmd.Flag(privateKeyFileFlag).Value.String(),
		)
		if err != nil {
			return err
		}

		err = generateCommand(params)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	if os.Getenv("SAB_DEBUG") == "TRUE" {
		log.SetLevel(log.DebugLevel)
	}
	log.Debugf("SAB_DEBUG=%s", os.Getenv("SAB_DEBUG"))
	generateCmd.Flags().IntP(expiryTimeFlag, "e", defaultExpiryTime, "The number of minutes the key will be valid for")
	generateCmd.Flags().StringP(publicKeyFileFlag, "p", defaultPublicKeyPEMFile, "The public key destination path (in PEM format)")
	generateCmd.Flags().StringP(privateKeyFileFlag, "j", defaultPrivateKeyPEMFile, "The projectId for the SA key")
	rootCmd.AddCommand(generateCmd)
}

func extractParams(eTs, puKs, prKs string) (GCParams, error) {
	expiryTime, err := strconv.Atoi(eTs)
	if err != nil {
		return GCParams{}, fmt.Errorf("invalid expirytime %v", err)
	}

	return GCParams{
		expiryTime:     expiryTime,
		publicKeyFile:  puKs,
		privateKeyFile: prKs,
	}, nil
}

func generateCommand(params GCParams) (err error) {
	log.Debugf("expiryTime: %d", params.expiryTime)
	log.Debugf("publicKeyFile: %s", params.publicKeyFile)
	log.Debugf("privateKeyFile: %s", params.privateKeyFile)

	public, private, err := certs.GenerateKeysAndCertExpiringIn(params.expiryTime)
	if err != nil {
		return err
	}

	saveKey(params.publicKeyFile, public)
	saveKey(params.privateKeyFile, private)

	return err
}

func saveKey(filename string, keyBites []byte) {
	publicPemFile, err := os.Create(filename)
	if err != nil {
		log.Printf("error when creating %s: %s \n", filename, err)
		os.Exit(1)
	}
	defer publicPemFile.Close()
	nB, err := publicPemFile.Write(keyBites)
	log.Debugf("wrote %d bytes", nB)
}



type privateJsonFields struct {
	ProjectId    string
	PrivateKeyId string
	PrivateKey   string
	ClientEmail  string
	ClientId     string
}

const privateJsonTemplate = `{
"type": "service_account",
"project_id": "{{.ProjectId}}",
"private_key_id": "{{.PrivateKeyId}}",
"private_key": "{{.PrivateKey}}",
"client_email": "{{.ClientEmail}}",
"client_id": "{{.ClientId}}",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://oauth2.googleapis.com/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/{{.ClientEmail}}"
}`

func jsonFormat(fields privateJsonFields) string {
	tmpl, err := template.New("test").Parse(privateJsonTemplate)
	if err != nil {
		panic(err)
	}
	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, fields)
	if err != nil {
		panic(err)
	}

	return buf.String()
}
