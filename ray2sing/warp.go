package ray2sing

import (
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func WarpSingbox(url string) (*T.Endpoint, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	getInt := func(key string) int {
		if v, ok := u.Params[key]; ok {
			i, _ := strconv.Atoi(v)
			return i
		}
		return 0
	}
	// fmt.Println(u.Username, "-", u.Password, "-", u.Params)
	out := T.Endpoint{
		Type: C.TypeWARP,
		Tag:  u.Name,
		Options: &T.WARPEndpointOptions{
			ServerOptions: T.ServerOptions{
				Server:     u.Hostname,
				ServerPort: u.Port,
			},
			UniqueIdentifier: u.Username,
			Noise:            getWireGuardNoise(u.Params, false),
			MTU:              uint32(toInt(getOneOfN(u.Params, "1280", "mtu"))),

			AWG: &T.AwgOptions{
				Jc:   getInt("jc"),
				Jmin: getInt("jmin"),
				Jmax: getInt("jmax"),

				S1: getInt("s1"),
				S2: getInt("s2"),
				S3: getInt("s3"),
				S4: getInt("s4"),
				H1: getOneOfN(u.Params, "", "h1"),
				H2: getOneOfN(u.Params, "", "h2"),
				H3: getOneOfN(u.Params, "", "h3"),
				H4: getOneOfN(u.Params, "", "h4"),

				I1: getOneOfN(u.Params, "", "i1"),
				I2: getOneOfN(u.Params, "", "i2"),
				I3: getOneOfN(u.Params, "", "i3"),
				I4: getOneOfN(u.Params, "", "i4"),
				I5: getOneOfN(u.Params, "", "i5"),
			},
		},
	}

	if out.Tag == "" {
		out.Tag = "WARP"
	}
	return &out, nil
}
