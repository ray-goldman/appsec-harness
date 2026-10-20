package client

import "crypto/tls"

var Cfg = &tls.Config{MinVersion: tls.VersionTLS12}
