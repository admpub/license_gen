package lib

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/webx-top/com"
)

// License check errors
var (
	ErrorLicenseRead  = errors.New("Could not read license")
	ErrorPrivKeyRead  = errors.New("Could not read private key")
	ErrorPubKeyRead   = errors.New("Could not read public key")
	ErrorMachineID    = errors.New("Could not read machine number")
	InvalidLicense    = errors.New("Invalid License file")
	UnlicensedVersion = errors.New("Unlicensed Version")
	InvalidMachineID  = errors.New("Invalid MachineID")
	InvalidLicenseID  = errors.New("Invalid LicenseID")
	ExpiredLicense    = errors.New("License expired")
)

type Validator interface {
	Validate() error
}

// LicenseInfo - Core information about a license
type LicenseInfo struct {
	Name       string    `json:"name,omitempty"`
	LicenseID  string    `json:"licenseID,omitempty"`
	MachineID  string    `json:"machineID,omitempty"`
	Version    string    `json:"version,omitempty"`
	Expiration time.Time `json:"expiration"`
	Extra      Validator `json:"extra,omitempty"`
}

func (a LicenseInfo) Remaining(langs ...string) *com.Durafmt {
	if a.Expiration.IsZero() {
		return nil
	}
	now := time.Now()
	duration := a.Expiration.Sub(now)
	//duration *= -1
	if len(langs) > 0 {
		return com.ParseDuration(duration, langs[0])
	}
	return com.ParseDuration(duration)
}

// LicenseData - This is the license data we serialise into a license file
type LicenseData struct {
	Info LicenseInfo `json:"info"`
	Key  string      `json:"key"`
}

// NewLicense from given info
func NewLicense(name string, expiry time.Time) *LicenseData {
	return &LicenseData{Info: LicenseInfo{Name: name, Expiration: expiry}}
}

func encodeKey(keyData []byte) string {
	return base64.StdEncoding.EncodeToString(keyData)
}

func decodeKey(keyStr string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(keyStr)
}

// Sign the License by updating the LicenseData.Key with given RSA private key
func (lic *LicenseData) Sign(pkey *rsa.PrivateKey) error {
	jsonLicInfo, err := json.Marshal(lic.Info)
	if err != nil {
		return err
	}

	signedData, err := Sign(pkey, jsonLicInfo)
	if err != nil {
		return err
	}

	lic.Key = encodeKey(signedData)

	return nil
}

// SignWithKey signs the License by updating the LicenseData.Key with given RSA
// private key read from a file
func (lic *LicenseData) SignWithKey(privKey string) error {
	rsaPrivKey, err := ReadPrivateKeyFromFile(privKey)
	if err != nil {
		return err
	}

	return lic.Sign(rsaPrivKey)
}

func (lic *LicenseData) ValidateLicenseKeyWithPublicKey(publicKey *rsa.PublicKey) error {
	signedData, err := decodeKey(lic.Key)
	if err != nil {
		return err
	}

	jsonLicInfo, err := json.Marshal(lic.Info)
	if err != nil {
		return err
	}

	return Unsign(publicKey, jsonLicInfo, signedData)
}

func (lic *LicenseData) ValidateLicenseKey(pubKey string) error {
	publicKey, err := ReadPublicKeyFromFile(pubKey)
	if err != nil {
		return err
	}

	return lic.ValidateLicenseKeyWithPublicKey(publicKey)
}

// CheckLicenseInfo checks license for logical errors such as for license expiry
func (lic *LicenseData) CheckLicenseInfo(versions ...string) error {
	if !lic.Info.Expiration.IsZero() && time.Now().After(lic.Info.Expiration) {
		return ExpiredLicense
	}
	if len(versions) > 0 && len(versions[0]) > 0 && len(lic.Info.Version) > 0 {
		if len(lic.Info.Version) > 1 {
			switch lic.Info.Version[0] {
			case '>':
				if len(lic.Info.Version) > 2 && lic.Info.Version[1] == '=' {
					if !com.VersionComparex(versions[0], lic.Info.Version[2:], `>=`) {
						return UnlicensedVersion
					}
					break
				}
				if !com.VersionComparex(versions[0], lic.Info.Version[1:], `>`) {
					return UnlicensedVersion
				}
			case '<':
				if len(lic.Info.Version) > 2 && lic.Info.Version[1] == '=' {
					if !com.VersionComparex(versions[0], lic.Info.Version[2:], `<=`) {
						return UnlicensedVersion
					}
					break
				}
				if !com.VersionComparex(versions[0], lic.Info.Version[1:], `<`) {
					return UnlicensedVersion
				}
			case '!':
				if len(lic.Info.Version) > 2 && lic.Info.Version[1] == '=' {
					if lic.Info.Version[2:] == versions[0] {
						return UnlicensedVersion
					}
					break
				}
				if lic.Info.Version[1:] == versions[0] {
					return UnlicensedVersion
				}
			default:
				if lic.Info.Version != versions[0] {
					return UnlicensedVersion
				}
			}
		} else {
			if lic.Info.Version != versions[0] {
				return UnlicensedVersion
			}
		}
	}

	if len(lic.Info.MachineID) > 0 {
		addrs, err := MACAddresses(false)
		if err != nil {
			return err
		}
		var valid bool
		for _, addr := range addrs {
			if lic.Info.MachineID == Hash(addr) {
				valid = true
				break
			}
		}
		if !valid {
			return InvalidMachineID
		}
	}

	if lic.Info.Extra != nil {
		return lic.Info.Extra.Validate()
	}

	return nil
}

func (lic *LicenseData) WriteLicense(w io.Writer) error {
	jsonLic, err := json.MarshalIndent(lic, "", "  ")
	if err != nil {
		return err
	}

	_, werr := fmt.Fprintf(w, "%s", string(jsonLic))
	return werr
}

func (lic *LicenseData) SaveLicenseToFile(licName string) error {
	jsonLic, err := json.MarshalIndent(lic, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(licName, jsonLic, 0644)
}

func ReadLicense(r io.Reader) (*LicenseData, error) {
	ldata, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var license LicenseData
	if err := json.Unmarshal(ldata, &license); err != nil {
		return nil, err
	}

	return &license, nil
}

func ReadLicenseFromFile(licFile string) (*LicenseData, error) {
	file, err := os.Open(licFile)
	defer file.Close()
	if err != nil {
		return nil, err
	}

	return ReadLicense(file)
}

func SignData(privKey string, data []byte) (string, error) {
	rsaPrivKey, err := ReadPrivateKey(strings.NewReader(privKey))
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return ``, err
	}

	signedData, err := Sign(rsaPrivKey, data)
	if err != nil {
		fmt.Println("Error signing data:", err)
		return ``, err
	}

	return encodeKey(signedData), nil
}

// Sign signs data with rsa-sha256
func Sign(r *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r, crypto.SHA256, d)
}

func UnsignData(pubKey string, signature string, data []byte) error {
	publicKey, err := ReadPublicKey(strings.NewReader(pubKey))
	if err != nil {
		return err
	}

	signedData, err := decodeKey(signature)
	if err != nil {
		return err
	}

	return Unsign(publicKey, data, signedData)
}

// Unsign verifies the message using a rsa-sha256 signature
func Unsign(r *rsa.PublicKey, message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r, crypto.SHA256, d, sig)
}

func MACAddresses(encoded bool) ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	hardwareAddrs := make([]string, 0)
	for _, inter := range interfaces {
		macAddr := fmt.Sprint(inter.HardwareAddr)
		if len(macAddr) == 0 {
			continue
		}
		if encoded {
			hardwareAddrs = append(hardwareAddrs, fmt.Sprintf(`%x`, macAddr))
			continue
		}
		hardwareAddrs = append(hardwareAddrs, macAddr)
	}
	return hardwareAddrs, err
}

// TestLicensingLogic  TODO: Move this to a proper test
func TestLicensingLogic(privKey, pubKey string) error {
	fmt.Println("*** TestLicensingLogic ***")

	expDate := time.Date(2017, 7, 16, 0, 0, 0, 0, time.UTC)
	licInfo := LicenseInfo{Name: "Chathura Colombage", Expiration: expDate}

	jsonLicInfo, err := json.Marshal(licInfo)
	if err != nil {
		fmt.Println("Error marshalling json data:", err)
		return err
	}

	rsaPrivKey, err := ReadPrivateKeyFromFile(privKey)
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return err
	}

	signedData, err := Sign(rsaPrivKey, jsonLicInfo)
	if err != nil {
		fmt.Println("Error signing data:", err)
		return err
	}

	signedDataBase64 := encodeKey(signedData)
	fmt.Println("Signed data:", signedDataBase64)

	// rsaPrivKey.Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts)

	// we need to sign jsonLicInfo using private key

	licData := LicenseData{Info: licInfo, Key: signedDataBase64}

	jsonLicData, err := json.MarshalIndent(licData, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling json data:", err)
		return err
	}

	fmt.Printf("License: \n%s\n", jsonLicData)

	backFromBase64, err := decodeKey(signedDataBase64)
	if err != nil {
		fmt.Println("Error decoding base64")
		return err
	}

	// Now we need to check whether we can verify this data or not
	publicKey, err := ReadPublicKeyFromFile(pubKey)
	if err != nil {
		return err
	}

	if err := Unsign(publicKey, backFromBase64, signedData); err != nil {
		fmt.Println("Couldn't Sign!")
	}

	return nil
}

func TestLicensing(privKey, pubKey string) error {
	fmt.Println("*** TestLicensingLogic ***")

	expDate := time.Date(2017, 7, 16, 0, 0, 0, 0, time.UTC)
	licInfo := LicenseInfo{Name: "Chathura Colombage", Expiration: expDate}
	licData := &LicenseData{Info: licInfo}

	if err := licData.SignWithKey(privKey); err != nil {
		fmt.Println("Couldn't update key")
		return err
	}

	fmt.Println("Key is:", licData.Key)

	if err := licData.ValidateLicenseKey(pubKey); err != nil {
		fmt.Println("Couldn't validate key")
		return err
	}

	fmt.Println("License is valid!")

	licData.Info.Name = "Chat Colombage"

	if err := licData.ValidateLicenseKey(pubKey); err != nil {
		fmt.Println("Couldn't validate key")
		return err
	}
	fmt.Println("License is still valid!")

	return nil
}

func CheckAndReturningLicense(licenseReader, pubKeyReader io.Reader, versions ...string) (*LicenseData, error) {
	lic, err := ReadLicense(licenseReader)
	if err != nil {
		return lic, ErrorLicenseRead
	}

	publicKey, err := ReadPublicKey(pubKeyReader)
	if err != nil {
		return lic, ErrorPubKeyRead
	}

	if err := lic.ValidateLicenseKeyWithPublicKey(publicKey); err != nil {
		return lic, InvalidLicense // we have a key mismatch here meaning license data is tampered
	}

	return lic, lic.CheckLicenseInfo(versions...)
}

// CheckLicense reads a license from licenseReader and then validate it against the
// public key read from pubKeyReader
func CheckLicense(licenseReader, pubKeyReader io.Reader, versions ...string) error {
	_, err := CheckAndReturningLicense(licenseReader, pubKeyReader, versions...)
	return err
}

func CheckLicenseStringAndReturning(license, pubKey string, versions ...string) (*LicenseData, error) {
	return CheckAndReturningLicense(strings.NewReader(license), strings.NewReader(pubKey), versions...)
}

// CheckLicenseString 检测授权文件是否有效
// license 为授权文件内容
// pubKey 为公钥内容
func CheckLicenseString(license, pubKey string, versions ...string) error {
	return CheckLicense(strings.NewReader(license), strings.NewReader(pubKey), versions...)
}

func Hash(raw string) string {
	return strings.ToUpper(com.Hash(fmt.Sprintf(`%x`, raw)))
}

// GenerateLicense 生成授权文件内容
// privKey 为私钥内容
func GenerateLicense(info *LicenseInfo, privKey string) ([]byte, error) {
	if len(info.MachineID) == 0 {
		addrs, err := MACAddresses(true)
		if err != nil {
			return nil, err
		}
		if len(addrs) < 1 {
			return nil, ErrorMachineID
		}
		info.MachineID = strings.ToUpper(com.Hash(addrs[0]))
	}
	data := &LicenseData{
		Info: *info,
	}
	rsaPrivKey, err := ReadPrivateKey(strings.NewReader(privKey))
	if err != nil {
		return nil, err
	}
	err = data.Sign(rsaPrivKey)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(data, "", "  ")
}
