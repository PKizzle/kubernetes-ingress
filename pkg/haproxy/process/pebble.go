package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/haproxytech/client-native/v6/runtime"
	"github.com/haproxytech/client-native/v6/runtime/options"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/api"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/env"
	"github.com/haproxytech/kubernetes-ingress/pkg/utils"
)

type pebbleControl struct {
	Env               env.Env
	OSArgs            utils.OSArgs
	masterSocket      runtime.Runtime
	masterSocketValid bool
	logger            utils.Logger
}

func newPebbleControl(env env.Env, osArgs utils.OSArgs) *pebbleControl {
	pb := pebbleControl{
		Env:    env,
		OSArgs: osArgs,
		logger: utils.GetLogger(),
	}

	masterSocket, err := runtime.New(context.Background(), options.MasterSocket(MASTER_SOCKET_PATH), options.AllowDelayedStart(time.Minute, time.Second))
	if err != nil {
		pb.logger.Error(err)
		return &pb
	}
	pb.masterSocketValid = true
	pb.masterSocket = masterSocket

	return &pb
}

func (d *pebbleControl) Service(action string) error {
	if d.OSArgs.Test {
		logger.Infof("HAProxy would be %sed now", action)
		return nil
	}
	var cmd *exec.Cmd

	switch action {
	case "start":
		// no need to start it is up already (pebble)
		return nil
	case "stop":
		// no need to stop it (pebble)
		return nil
	case "reload":
		if d.masterSocketValid {
			// Enhanced reload with better error handling and diagnostics
			d.logger.Tracef("Attempting masterSocket.Reload() operation via pebble")

			// Before reload, capture more diagnostic information
			if debugResult, debugErr := d.masterSocket.ExecuteRaw("show stats"); debugErr == nil {
				d.logger.Tracef("HAProxy stats response length: %d bytes", len(debugResult))
			}

			// Try raw reload command to see exact response
			if reloadRawResult, reloadRawErr := d.masterSocket.ExecuteRaw("reload"); reloadRawErr == nil {
				d.logger.Tracef("Raw reload command response: %q (length: %d)", string(reloadRawResult), len(reloadRawResult))
			} else {
				d.logger.Errorf("Raw reload command failed: %v", reloadRawErr)
			}

			// Perform the actual reload using the library
			msg, err := d.masterSocket.Reload()
			if err != nil {
				d.logger.Errorf("masterSocket.Reload() failed: %v", err)

				// Provide detailed error analysis with enhanced diagnostics
				if strings.Contains(err.Error(), "unknown status") {
					d.logger.Errorf("HAProxy returned unknown status - detailed diagnostics:")
					d.logger.Errorf("  Error details: %q", err.Error())
					d.logger.Errorf("  This may indicate:")
					d.logger.Errorf("    1. Client-native library parsing issue")
					d.logger.Errorf("    2. HAProxy response format incompatibility")
					d.logger.Errorf("    3. Empty or malformed reload response")

					// Get HAProxy version for compatibility analysis
					if versionResult, versionErr := d.masterSocket.ExecuteRaw("show version"); versionErr == nil {
						d.logger.Errorf("  HAProxy version: %q", string(versionResult))
					}
				}

				d.logger.Errorf("Falling back to pebble signal for reload")
			} else {
				d.logger.Debug("Reload done via master socket")
				d.logger.Debug(msg)
				d.logger.Tracef("masterSocket.Reload() completed successfully")
				return nil
			}
		}
		cmd = exec.Command("pebble", "signal", "SIGUSR2", "haproxy")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	default:
		return fmt.Errorf("unknown command '%s'", action)
	}
}

func (d *pebbleControl) UseAuxFile(useAuxFile bool) {
	// do nothing we always have it
}

func (d *pebbleControl) SetAPI(api api.HAProxyClient) {
	// unused
}
