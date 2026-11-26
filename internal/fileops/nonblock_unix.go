//go:build !windows

package fileops

import "syscall"

const nonblockFlag = syscall.O_NONBLOCK
