package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/admpub/license_gen/lib"
)

/*
step 1. gen -type cert
step 2. gen -type license  -name admpub -expiry 2020-12-30
*/

var (
	typePtr = flag.String("type", "cert", "Operation type. Valid values are license or certificate.")
	licFile = flag.String("lic", "license.json", "License file name. Required for license generation.")
	certKey = flag.String("cert", "cert.pem", "Public certificate key.")
	privKey = flag.String("key", "key.pem", "Certificate key file. Required for license generation.")
	rsaBits = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Only used when type is certificate.")

	// License
	id      = flag.String("id", "", "License ID for the License")
	machine = flag.String("machine", "", "Machine ID for the License")
	version = flag.String("version", "", "Licensed Version No.")
	hashed  = flag.Bool("hashed", false, "Machine ID for the License")

	// Required info for license generation
	name    = flag.String("name", "", "Name of the Licensee")
	expDate = flag.String("expiry", "", "Expiry date for the License. Expected format is 2006-1-02")

	verbose = flag.Bool("verbose", true, "Print verbose messages")
)

func main() {
	flag.Parse()

	switch *typePtr {
	case "lic", "license":
		fmt.Println("Generating license")
		if err := generateLicense(); err != nil {
			fmt.Println("Error generating license:", err)
		}
	case "cert", "certificate":
		if err := generateCertificate(); err != nil {
			fmt.Fprintf(os.Stderr, "Certificate generation failed: %s\n", err)
			os.Exit(1)
		}
	case "test":
		hasError := false
		if _, err := lib.ReadPublicKeyFromFile("cert.pem"); err != nil {
			fmt.Println("Error reading public key:", err)
			hasError = true
		}

		if _, err := lib.ReadPrivateKeyFromFile("key.pem"); err != nil {
			fmt.Println("Error reading private key:", err)
			hasError = true
		}

		if hasError {
			os.Exit(1)
		}
	default:
		if *typePtr == "" {
			fmt.Fprintf(os.Stderr, "Operation type required\n")
		} else {
			fmt.Fprintf(os.Stderr, "Invalid operation type: '%s'\n", *typePtr)
		}
		os.Exit(1)
	}
}

func generateCertificate() error {
	fmt.Println("Generating x509 Certificate")
	return lib.GenerateCertificate("cert.pem", "key.pem", *rsaBits)
}

func generateLicense() error {
	if len(*name) == 0 {
		return fmt.Errorf("Licensee name is empty")
	}

	date, err := time.Parse("2006-1-02", *expDate)
	if err != nil {
		return err
	}

	lic := lib.NewLicense(*name, date)
	lic.Info.MachineID = *machine
	lic.Info.LicenseID = *id
	lic.Info.Version = *version
	if len(lic.Info.MachineID) == 0 {
		addrs, err := lib.MACAddresses(false)
		if err != nil {
			return err
		}
		if len(addrs) > 0 {
			lic.Info.MachineID = lib.Hash(addrs[0])
		}
	} else if *hashed == false {
		lic.Info.MachineID = lib.Hash(lic.Info.MachineID)
	}

	if *verbose {
		fmt.Println("Licensee:", *name)
		fmt.Println("Machine ID:", lic.Info.MachineID)
		fmt.Println("License ID:", lic.Info.LicenseID)
		fmt.Println("Expiry date:", date)
		fmt.Println("Signing with private key:", *privKey)
	}

	if err := lic.SignWithKey(*privKey); err != nil {
		return err
	}

	if *verbose {
		fmt.Println("Signing OK. Saving License to:", *licFile)
		fmt.Println("*** BEGIN LICENSE ***")
		lic.WriteLicense(os.Stdout)
		fmt.Println("\n*** END LICENSE ***")
	}

	return lic.SaveLicenseToFile(*licFile)
}
