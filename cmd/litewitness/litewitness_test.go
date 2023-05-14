package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"litewitness": func() (exitCode int) {
			main()
			return 0
		},
	}))
}

func TestScript(t *testing.T) {
	p := testscript.Params{
		Dir: "testdata",
		Setup: func(e *testscript.Env) error {
			bindir := filepath.SplitList(os.Getenv("PATH"))[0]
			// Coverage is not collected because of https://go.dev/issue/60182.
			cmd := exec.Command("go", "build", "-o", bindir)
			if testing.CoverMode() != "" {
				cmd.Args = append(cmd.Args, "-cover")
			}
			cmd.Args = append(cmd.Args, "filippo.io/litetlog/cmd/witnessctl")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"waitfor": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 1 {
					ts.Fatalf("usage: waitfor <file | host:port>")
				}
				protocol := "unix"
				if strings.Contains(args[0], ":") {
					protocol = "tcp"
				}
				var lastErr error
				for i := 0; i < 50; i++ {
					conn, err := net.Dial(protocol, args[0])
					if err == nil {
						conn.Close()
						return
					}
					time.Sleep(100 * time.Millisecond)
					lastErr = err
				}
				ts.Fatalf("timeout waiting for %s: %v", args[0], lastErr)
			},
			"killall": func(ts *testscript.TestScript, neg bool, args []string) {
				for _, cmd := range ts.BackgroundCmds() {
					cmd.Process.Signal(os.Interrupt)
				}
			},
			"linecount": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 2 {
					ts.Fatalf("usage: linecount <file> N")
				}
				count, err := strconv.Atoi(args[1])
				if err != nil {
					ts.Fatalf("invalid count: %v", args[1])
				}
				if got := strings.Count(ts.ReadFile(args[0]), "\n"); got != count {
					ts.Fatalf("%v has %d lines, not %d", args[0], got, count)
				}
			},
		},
	}
	testscript.Run(t, p)
}
