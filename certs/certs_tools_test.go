package certs

import (
	"crypto/x509"
	"testing"
	"time"
)

func Test_certTemplate(t *testing.T) {
	now := time.Now()
	type args struct {
		notBefore time.Time
		notAfter  time.Time
	}
	tests := []struct {
		name    string
		args    args
		want    x509.Certificate
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				notBefore: now,
				notAfter:  now.Add(5 * time.Minute),
			},
			want: x509.Certificate{
				NotBefore: now,
				NotAfter:  now.Add(5 * time.Minute),
			},
			wantErr: false,
		},
		{
			name: "invalid",
			args: args{
				notBefore: now,
				notAfter:  now.Add(-5 * time.Minute),
			},
			want:    x509.Certificate{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := certTemplate(tt.args.notBefore, tt.args.notAfter)
			if (err != nil) != tt.wantErr {
				t.Errorf("certTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !validDates(got, tt.want) {
				t.Errorf("certTemplate() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func validDates(got, want x509.Certificate) bool {
	return got.NotBefore.Equal(want.NotBefore) && got.NotAfter.Equal(want.NotAfter)
}
