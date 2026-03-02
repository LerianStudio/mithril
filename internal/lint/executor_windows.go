//go:build windows

package lint

import "os/exec"

func configureProcessGroup(cmd *exec.Cmd) {
	_ = cmd
}

func terminateProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
