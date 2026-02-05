package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func PsiphonSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	opts := T.PsiphonOutboundOptions{
		// ServerOptions: u.GetServerOption(),
		EgressRegion:                       getOneOfN(u.Params, "", "region"),
		RemoteServerListURL:                getOneOfN(u.Params, "", "remote_server_list_url"),
		RemoteServerListDownloadFilename:   getOneOfN(u.Params, "", "remote_server_list_download_filename"),
		RemoteServerListSignaturePublicKey: getOneOfN(u.Params, "", "remote_server_list_signature_public_key"),
	}
	out := &T.Outbound{
		Type:    C.TypePsiphon,
		Tag:     u.Name,
		Options: &opts,
	}

	return out, nil
}
