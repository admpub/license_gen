package lib

import "errors"

var (
	ErrHostParameterRequired     = errors.New("Host parameter is required")
	ErrUnrecognizedEllipticCurve = errors.New("Unrecognized elliptic curve")
	ErrParsingPublicKey          = errors.New("Error parsing public key")
	ErrLicenseRead               = errors.New("Could not read license")
	ErrPrivKeyRead               = errors.New("Could not read private key")
	ErrPubKeyRead                = errors.New("Could not read public key")
	ErrPrivKey                   = errors.New("Invalid private key")
	ErrPubKey                    = errors.New("Invalid public key")
	ErrMachineID                 = errors.New("Could not read machine number")
	ErrInvalidLicense            = errors.New("Invalid License file")
	ErrUnlicensedVersion         = errors.New("Unlicensed Version")
	ErrInvalidMachineID          = errors.New("Invalid MachineID")
	ErrInvalidLicenseID          = errors.New("Invalid LicenseID")
	ErrInvalidDomain             = errors.New("Invalid Domain")
	ErrExpiredLicense            = errors.New("License expired")
)
