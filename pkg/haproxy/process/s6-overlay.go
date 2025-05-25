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
			// Enhanced reload with detailed error handling and retry logic
			var reloadErr error
			maxRetries := 2
			retryDelay := time.Millisecond * 100

			for attempt := 0; attempt <= maxRetries; attempt++ {
				if attempt > 0 {
					d.logger.Debugf("Retry attempt %d/%d for masterSocket reload", attempt, maxRetries)
					time.Sleep(retryDelay)
					retryDelay *= 2 // Exponential backoff
				}

				func() {
					defer func() {
						if r := recover(); r != nil {
							// Enhanced panic logging with stack trace
							stackTrace := debug.Stack()
							d.logger.Errorf("masterSocket.Reload() panicked on attempt %d: %v", attempt+1, r)
							d.logger.Errorf("Panic stack trace: %s", string(stackTrace))

							// Log detailed panic information
							if panicErr, ok := r.(error); ok {
								if strings.Contains(panicErr.Error(), "slice bounds out of range") {
									d.logger.Errorf("Detected slice bounds panic - this may indicate empty output from HAProxy reload command")
								} else if strings.Contains(panicErr.Error(), "index out of range") {
									d.logger.Errorf("Detected index out of range panic - this may indicate malformed response from HAProxy")
								}
							}

							reloadErr = fmt.Errorf("runtime reload panicked on attempt %d: %v", attempt+1, r)
						}
					}()

					// Check master socket connectivity before reload
					d.logger.Tracef("Checking master socket connectivity before reload attempt %d", attempt+1)

					// Test basic connectivity with a simple command
					if testResult, testErr := d.masterSocket.ExecuteRaw("show info"); testErr != nil {
						d.logger.Errorf("Master socket connectivity test failed on attempt %d: %v", attempt+1, testErr)
						reloadErr = fmt.Errorf("master socket connectivity test failed: %v", testErr)
						return
					} else {
						d.logger.Tracef("Master socket connectivity test passed on attempt %d (response length: %d)", attempt+1, len(testResult))
					}

					d.logger.Tracef("Attempting masterSocket.Reload() operation (attempt %d)", attempt+1)

					// Before reload, let's try to get more detailed response information
					if debugResult, debugErr := d.masterSocket.ExecuteRaw("show stats"); debugErr == nil {
						d.logger.Tracef("HAProxy stats response length: %d bytes", len(debugResult))
					}

					// Also try a reload command manually to see raw response
					if reloadRawResult, reloadRawErr := d.masterSocket.ExecuteRaw("reload"); reloadRawErr == nil {
						d.logger.Tracef("Raw reload command response: %q (length: %d)", string(reloadRawResult), len(reloadRawResult))
					} else {
						d.logger.Errorf("Raw reload command failed: %v", reloadRawErr)
					}

					// Perform the actual reload using the library
					msg, err := d.masterSocket.Reload()
					if err == nil {
						d.logger.Debug(msg)
						d.logger.Tracef("masterSocket.Reload() completed successfully on attempt %d", attempt+1)
						reloadErr = nil
					} else {
						d.logger.Errorf("masterSocket.Reload() returned error on attempt %d: %v", attempt+1, err)

						// Provide detailed error analysis with raw response capture
						if strings.Contains(err.Error(), "unknown status") {
							d.logger.Errorf("HAProxy returned unknown status - detailed diagnostics:")
							d.logger.Errorf("  Error details: %q", err.Error())
							d.logger.Errorf("  This may indicate:")
							d.logger.Errorf("    1. HAProxy reload command response format changed")
							d.logger.Errorf("    2. Client-native library version compatibility issue")
							d.logger.Errorf("    3. HAProxy returned unexpected status format")
							d.logger.Errorf("    4. Empty or truncated response from HAProxy")

							// Try to get HAProxy version to check compatibility
							if versionResult, versionErr := d.masterSocket.ExecuteRaw("show version"); versionErr == nil {
								d.logger.Errorf("  HAProxy version info: %q", string(versionResult))
							}
						} else if strings.Contains(err.Error(), "connection refused") {
							d.logger.Errorf("Master socket connection refused - HAProxy may not be running properly")
						} else if strings.Contains(err.Error(), "timeout") {
							d.logger.Errorf("Master socket timeout - HAProxy may be overloaded or unresponsive")
						}

						reloadErr = err
					}
				}()

				// If reload succeeded, break out of retry loop
				if reloadErr == nil {
					return nil
				}

				// If this is the last attempt or a permanent error, don't retry
				if attempt == maxRetries || isPermanentError(reloadErr) {
					break
				}
			}

			// All retry attempts failed - decide whether to invalidate the master socket
			if isPermanentError(reloadErr) {
				d.logger.Errorf("Permanent error detected, invalidating master socket: %v", reloadErr)
				d.masterSocketValid = false
			} else {
				d.logger.Errorf("Transient error detected, keeping master socket valid for next attempt: %v", reloadErr)
			}

			d.logger.Errorf("masterSocket reload failed after %d attempts, falling back to s6-svc reload: %v", maxRetries+1, reloadErr)
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

// isPermanentError determines if an error is permanent and should invalidate the master socket
func isPermanentError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Permanent errors that indicate the master socket should be invalidated
	permanentErrors := []string{
		"connection refused",
		"no such file or directory",
		"permission denied",
		"broken pipe",
		"connection reset by peer",
	}

	for _, permErr := range permanentErrors {
		if strings.Contains(errStr, permErr) {
			return true
		}
	}

	// Transient errors that might resolve on retry
	// "unknown status" can often be transient due to timing issues
	return false
}
