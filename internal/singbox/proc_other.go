//go:build !windows

package singbox

import "os/exec"

func hideWindow(cmd *exec.Cmd) {}
