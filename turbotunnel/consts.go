package turbotunnel

import "errors"

const queueSize = 64

var errClosedPacketConn = errors.New("operation on closed connection")
var errNotImplemented = errors.New("not implemented")
