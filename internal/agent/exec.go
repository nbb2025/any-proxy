package agent

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

func runCommand(ctx context.Context, args []string, logger Logger) error {
	if len(args) == 0 {
		return nil
	}
	cmdCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}

	cmd := exec.CommandContext(cmdCtx, args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if logger != nil && len(output) > 0 {
		logger.Printf("[agent] command output: %s", string(output))
	}
	if err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	return nil
}
