package ray2sing

// func ParseTurnURL(turnURL string) (*T.TurnRelayOptions, error) {
// 	// Parse the URL
// 	if turnURL == "" {
// 		return nil, nil
// 	}
// 	parsedURL, err := url.Parse(turnURL)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Check if the URL scheme is "turn"
// 	if parsedURL.Scheme != "turn" {
// 		return nil, E.New("Invalid URL scheme:", parsedURL.Scheme)
// 	}

// 	// Extract the username and password from the URL
// 	username := parsedURL.User.Username()
// 	password, _ := parsedURL.User.Password()

// 	// Extract the host and port from the URL
// 	hostAndPort := strings.Split(parsedURL.Host, ":")
// 	if len(hostAndPort) != 2 {
// 		return nil, E.New("Invalid host:port format")
// 	}
// 	server := hostAndPort[0]
// 	serverPort, err := strconv.ParseUint(hostAndPort[1], 10, 16)
// 	if err != nil {
// 		return nil, E.New("Invalid server port:", serverPort)
// 	}
// 	// Extract the realm query parameter
// 	realm := parsedURL.Query().Get("realm")

// 	// Create a TurnRelayOptions struct
// 	relayOptions := &T.TurnRelayOptions{
// 		ServerOptions: &T.ServerOptions{
// 			Server:     server,
// 			ServerPort: uint16(serverPort),
// 		},
// 		Username: username,
// 		Password: password,
// 		Realm:    realm,
// 	}

// 	return relayOptions, nil
// }
