package client

import "crypto/tls"

var Cfg = &tls.Config{InsecureSkipVerify: true}
