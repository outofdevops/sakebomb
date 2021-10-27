package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	"google.golang.org/api/iam/v1"
	"sakebomb/certs"
	"strconv"
	"strings"
)

const (
	projectIdFlag  = "project-id"
	saEmailFlag    = "sa-email"
	jsonPrivateKey = "private-key-file"
	defaultKeyPath = "sake.json"
)

type SAParams struct {
	expiryTime     int
	projectId      string
	saEmail        string
	jsonPrivateKey string
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a Service Account Key in GCP",
	Long:  fmt.Sprintf("Generates a Service Account Key Pair and uploads it to Google"),
	RunE: func(cmd *cobra.Command, args []string) error {
		params, err := extractCreateParams(cmd.Flag(expiryTimeFlag).Value.String(),
			cmd.Flag(projectIdFlag).Value.String(),
			cmd.Flag(saEmailFlag).Value.String(),
			cmd.Flag(jsonPrivateKey).Value.String(),
		)
		if err != nil {
			return err
		}

		err = createSAInGCP(params)
		if err != nil {
			return err
		}
		return nil
	},
}

func extractCreateParams(eTs, pId, sa, jsonDest string) (SAParams, error) {
	expiryTime, err := strconv.Atoi(eTs)
	if err != nil {
		return SAParams{}, fmt.Errorf("invalid expirytime %v", err)
	}

	return SAParams{
		expiryTime:     expiryTime,
		projectId:      pId,
		saEmail:        sa,
		jsonPrivateKey: jsonDest,
	}, nil
}

func init() {
	createCmd.Flags().IntP(expiryTimeFlag, "e", defaultExpiryTime, "The number of minutes the key will be valid for")
	createCmd.Flags().StringP(projectIdFlag, "p", "", "The Google ProjectID")
	createCmd.Flags().StringP(jsonPrivateKey, "j", defaultKeyPath, "The path for the private key")
	createCmd.Flags().StringP(saEmailFlag, "s", "", "The SA email")
	createCmd.MarkFlagRequired(projectIdFlag)
	createCmd.MarkFlagRequired(saEmailFlag)
	rootCmd.AddCommand(createCmd)
}

func createSAInGCP(params SAParams) error {
	public, private, err := certs.GenerateKeysAndCertExpiringIn(params.expiryTime)
	if err != nil {
		return fmt.Errorf("while generating key: %+v", err)
	}

	saName := fmt.Sprintf("projects/%s/serviceAccounts/%s", params.projectId, params.saEmail)

	keyId, err := uploadKeyToServiceAccount(saName, base64.StdEncoding.EncodeToString(public))
	if err != nil {
		return fmt.Errorf("while uploading key: %+v", err)
	}

	uniqueId, err := getSAUniqueId(saName)
	if err != nil {
		return fmt.Errorf("getting Service Account: %+v", err)
	}

	json := jsonFormat(privateJsonFields{
		ProjectId:    params.projectId,
		PrivateKeyId: keyId,
		PrivateKey:   strings.Replace(string(private), "\n", "\\n", -1),
		ClientEmail:  params.saEmail,
		ClientId:     uniqueId,
	})
	saveKey(params.jsonPrivateKey, []byte(json))
	return nil
}

func uploadKeyToServiceAccount(saName, publicKeyData string) (string, error) {
	iamService, err := iam.NewService(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to initiate IAM client SDK: %v", err)
	}
	keyService := iam.NewProjectsServiceAccountsKeysService(iamService)

	uploadKeyRequest := &iam.UploadServiceAccountKeyRequest{
		PublicKeyData: publicKeyData,
	}

	res, err := keyService.Upload(saName, uploadKeyRequest).Do()
	if err != nil {
		return "", fmt.Errorf("failed to upload key to service account: %v", err)
	}

	return strings.TrimPrefix(res.Name, saName+"/keys/"), nil
}

func getSAUniqueId(saName string) (string, error) {
	iamService, err := iam.NewService(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to initiate IAM client SDK: %v", err)
	}
	res, err := iamService.Projects.ServiceAccounts.Get(saName).Do()
	if err != nil {
		return "", fmt.Errorf("Projects.ServiceAccounts.Get: %v", err)
	}

	return res.UniqueId, nil
}
