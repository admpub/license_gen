package lib

type DefaultValidator struct {
	*LicenseData
	NowVersions []string
}

func (v *DefaultValidator) Validate() error {
	if err := v.CheckExpiration(); err != nil {
		return err
	}
	if err := v.CheckVersion(v.NowVersions...); err != nil {
		return err
	}
	if err := v.CheckMAC(); err != nil {
		return err
	}
	return nil
}
