package lib_test

import (
	"strings"
	"testing"
	"time"

	"github.com/admpub/license_gen/lib"
)

var testLicense = `{
  "info": {
    "name": "Chathura Colombage",
    "expiration": "2017-07-16T00:00:00Z"
  },
  "key": "T7GkDY24W9mp9+usPmS46lN4sIEEtIVyVVnW7cslOBJyyWH2QLZCSN3vdkty4rg/CVgrUoGYJBAiFu5ku+lxxfK6W6I+6v6F/LENr8HFO+aBIN1MnGZcdVBdRHZKVTHJNmme4EDOJ4pv0eWNNP3h/ia4vzDuN/pRIcGxQn/DrjVK+cjn/6XGAaG6u1TmUTuN5XHJVnYphQ8jCN4C8W7TOlit/svcAWGybtQKouUk/491ckRtJxID+OTrQyW0mmZrBj/9Gsr1+Rpl/F1vjELUzImuTXHkFf1gyc35U/Ql2Qs+ys91VWc1wK8atnyHjazXCSs+/j83u+4D5QUTzxBnRQ=="
}
`

func TestReadLicense(t *testing.T) {
	r := strings.NewReader(testLicense)

	lic, err := lib.ReadLicense(r)
	if err != nil {
		t.Error("Error reading license file:", err)
	}

	if lic.Info.Name != "Chathura Colombage" {
		t.Error("Name does not match!")
	}

	if lic.Key == "" {
		t.Error("Key is empty!")
	}

	if lic.Info.Expiration != time.Date(2017, 7, 16, 0, 0, 0, 0, time.UTC) {
		t.Error("Expiration date is different!")
	}
}

func TestValidateLicenseKeyWithPublicKey(t *testing.T) {
	r := strings.NewReader(testLicense)
	lic, err := lib.ReadLicense(r)

	if err != nil {
		t.Error("Couldn't read license!")
	}

	rk := strings.NewReader(pubKey)
	pk, err2 := lib.ReadPublicKey(rk)
	if err2 != nil {
		t.Error("Coudln't read public key!")
	}

	if err := lic.ValidateLicenseKeyWithPublicKey(pk); err != nil {
		t.Error("License validation failed:", err)
	}
}

func TestCheckLicense(t *testing.T) {
	lreader := strings.NewReader(testLicense)
	pkreader := strings.NewReader(pubKey)

	err := lib.CheckLicense(lreader, pkreader, nil)
	if err != nil {
		t.Errorf("Expected nil error, but found %s\n", err)
	}
}
