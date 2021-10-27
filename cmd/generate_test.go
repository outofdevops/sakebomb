package cmd

import (
	"reflect"
	"strconv"
	"testing"
)

func Test_generateCommand(t *testing.T) {
	type args struct {
		gcParams GCParams
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "no flags default values",
			args: args{
				gcParams: GCParams{
					expiryTime:     defaultExpiryTime,
					publicKeyFile:  defaultPublicKeyPEMFile,
					privateKeyFile: defaultPrivateKeyPEMFile,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := generateCommand(tt.args.gcParams)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_extractParams(t *testing.T) {
	type args struct {
		eTs, puKs, prKs string
	}
	tests := []struct {
		name    string
		args    args
		want    GCParams
		wantErr bool
	}{
		{
			name: "default fields",
			args: args{
				strconv.Itoa(defaultExpiryTime), defaultPrivateKeyPEMFile, defaultPrivateKeyPEMFile,
			},
			want: GCParams{
				defaultExpiryTime, defaultPrivateKeyPEMFile, defaultPrivateKeyPEMFile,
			},
			wantErr: false,
		}, {
			name: "invalid expiryTime",
			args: args{
				"invalidInt", defaultPrivateKeyPEMFile, defaultPrivateKeyPEMFile,
			},
			want:    GCParams{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractParams(tt.args.eTs, tt.args.puKs, tt.args.prKs)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractParams() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_jsonFormat(t *testing.T) {
	expected := `{
"type": "service_account",
"project_id": "a",
"private_key_id": "b",
"private_key": "c",
"client_email": "d",
"client_id": "e",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://oauth2.googleapis.com/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/d"
}`

	type args struct {
		fields privateJsonFields
	}
	tests := []struct {
		name string
		want string
		args args
	}{
		{
			name: "Valid",
			want: expected,
			args: args{
				fields: privateJsonFields{
					ProjectId:    "a",
					PrivateKeyId: "b",
					PrivateKey:   "c",
					ClientEmail:  "d",
					ClientId:     "e",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jsonFormat(tt.args.fields)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("jsonFormat() got = %v, want %v", got, tt.want)
			}
		})
	}
}
