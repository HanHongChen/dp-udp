package model

import "errors"

var (
	ErrInvalidPacketSize = errors.New("invalid packet size")
	ErrDuplicatePacket   = errors.New("duplicate packet detected")
	ErrOutOfOrderPacket  = errors.New("out of order packet")
)