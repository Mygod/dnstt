//go:build !android
// +build !android

package main

import "syscall"

var dialerControlVpn func(network, address string, c syscall.RawConn) error = nil
