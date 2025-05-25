package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"

	"github.com/haproxytech/client-native/v6/runtime"
	"github.com/haproxytech/client-native/v6/runtime/options"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/api"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/env"
	"github.com/haproxytech/kubernetes-ingress/pkg/utils"
)

type s6Control struct {
	API               api.HAProxyClient
	Env               env.Env
	OSArgs            utils.OSArgs
	masterSocket      runtime.Runtime
	masterSocketValid bool
	logger            utils.Logger
}

func newS6Control(api api.HAProxyClient, env env.Env, osArgs utils.OSArgs) *s6Control {
	sc := s6Control{
		API:    api,
		Env:    env,
		OSArgs: osArgs,
		logger: utils.GetLogger(),
	}

	masterSocket, err := runtime.New(context.Background(), options.MasterSocket(MASTER_SOCKET_PATH), options.AllowDelayedStart(time.Minute, time.Second))
	if err != nil {
		sc.logger.Error(err)
		return &sc
	}
	sc.masterSocketValid = true
	sc.masterSocket = masterSocket

	return &sc
}

func (d *s6Control) Service(action string) error {
	if d.OSArgs.Test {
		logger.Infof("HAProxy would be %sed now", action)
		return nil
	}
	var cmd *exec.Cmd

	switch action {
	case "start":
		// no need to start it is up already (s6)
		return nil
	case "stop":
		// no need to stop it (s6)
		return nil
	case "reload":
		if d.masterSocketValid {
			// Enhanced panic recovery for client-native runtime reload
			var reloadErr error
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Enhanced panic logging with stack trace
						stackTrace := debug.Stack()
						d.logger.Errorf("masterSocket.Reload() panicked: %v", r)
						d.logger.Errorf("Panic stack trace: %s", string(stackTrace))

						// Log detailed panic information
						if panicErr, ok := r.(error); ok && strings.Contains(panicErr.Error(), "slice bounds out of range") {
							d.logger.Errorf("Detected slice bounds panic - this may indicate empty output from HAProxy reload command")
						}

						d.masterSocketValid = false
						reloadErr = fmt.Errorf("runtime reload panicked: %v", r)
					}
				}()

				d.logger.Tracef("Attempting masterSocket.Reload() operation")
				msg, err := d.masterSocket.Reload()
				if err == nil {
					d.logger.Debug(msg)
					d.logger.Tracef("masterSocket.Reload() completed successfully")
					reloadErr = nil
				} else {
					d.logger.Errorf("masterSocket.Reload() returned error: %v", err)
					reloadErr = err
				}
			}()

			if reloadErr == nil {
				return nil
			}
			d.logger.Errorf("masterSocket reload failed, falling back to s6-svc reload: %v", reloadErr)
		}

		cmd = exec.Command("s6-svc", "-2", "/run/service/haproxy")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	default:
		return fmt.Errorf("unknown command '%s'", action)
	}
}

func (d *s6Control) UseAuxFile(useAuxFile bool) {
	// do nothing we always have it
}

func (d *s6Control) SetAPI(api api.HAProxyClient) {
	d.API = api
}
