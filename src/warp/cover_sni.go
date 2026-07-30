package warp

type CoverSNIMode string

const (
	CoverCanonical    CoverSNIMode = "canonical"
	CoverBuiltin      CoverSNIMode = "builtin"
	CoverUserExplicit CoverSNIMode = "user-explicit"
)

type CoverSNIConfig struct {
	Mode                           CoverSNIMode
	Name, EndpointPin, DataVersion string
}

func (c CoverSNIConfig) Valid() bool {
	return c.Mode != "" && c.Name != "" && c.EndpointPin != "" && c.DataVersion != ""
}
func (c CoverSNIConfig) Insecure() bool { return c.EndpointPin == "" }
