package GoSNMPServer

import "github.com/pkg/errors"

var ErrUnsupportedProtoVersion = errors.New("ErrUnsupportedProtoVersion")
var ErrNoSNMPInstance = errors.New("ErrNoSNMPInstance")
var ErrUnsupportedOperation = errors.New("ErrUnsupportedOperation")
var ErrNoPermission = errors.New("ErrNoPermission")
var ErrUnsupportedPacketData = errors.New("ErrUnsupportedPacketData")

// ErrWrongType is returned, wrapped or not, by an OnSet handler refusing a value
// whose type the item does not accept. The SET is answered wrongType (RFC 3416
// §4.2.5) rather than the genErr any other handler error gets.
var ErrWrongType = errors.New("ErrWrongType")
