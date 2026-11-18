// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logid"
	"tailscale.com/util/must"
	"tailscale.com/util/zstdframe"
)

// TestNetLogTarget checks that network flow logs go to the
// [nodecap.LogFlowsTarget] control sends. An upload to Tailscale's log
// service instead would go through the env's traffic trap and fail the test.
func TestNetLogTarget(t *testing.T) {
	tstest.Parallel(t)
	domainID := must.Get(logid.NewPrivateID())
	env := NewTestEnv(t, ConfigureControl(func(s *testcontrol.Server) {
		s.ModifyFirstMapResponse = func(res *tailcfg.MapResponse, _ *tailcfg.MapRequest) {
			res.DomainDataPlaneAuditLogID = domainID.String()
		}
	}))

	var mu sync.Mutex
	uploads := map[string][]byte{} // request URI => last decoded body
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Encoding") == "zstd" {
			body, _ = zstdframe.AppendDecode(nil, body)
		}
		mu.Lock()
		uploads[r.URL.RequestURI()] = body
		mu.Unlock()
	}))
	defer target.Close()

	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()
	n1.AwaitListening()
	n1.MustUp()
	n1.AwaitRunning()
	n2 := NewTestNode(t, env)
	d2 := n2.StartDaemon()
	n2.AwaitListening()
	n2.MustUp()
	n2.AwaitRunning()
	ip2 := n2.AwaitIP4().String()

	nodeID := must.Get(logid.NewPrivateID())
	self := env.Control.Node(n1.MustStatus().Self.PublicKey)
	self.DataPlaneAuditLogID = nodeID.String()
	env.Control.UpdateNode(self)
	env.Control.SetNodeCapMap(self.Key, tailcfg.NodeCapMap{
		nodecap.DataPlaneAuditLogs: nil,
		nodecap.LogFlowsTarget:     {tailcfg.RawMessage(`"` + target.URL + `/netlog/"`)},
	})

	want := "/netlog/c/tailtraffic.log.tailscale.io/" + nodeID.String() + "?copyId=" + domainID.String()
	if err := tstest.WaitFor(30*time.Second, func() error {
		// ICMP crosses the TUN, so the logger records a virtual connection.
		n1.Tailscale("ping", "--icmp", "--timeout=1s", ip2).Run()
		mu.Lock()
		defer mu.Unlock()
		for uri, body := range uploads {
			if uri != want {
				return fmt.Errorf("upload to %q, want %q", uri, want)
			}
			if bytes.Contains(body, []byte(ip2)) {
				return nil
			}
		}
		return fmt.Errorf("no flow to %s in %d uploads", ip2, len(uploads))
	}); err != nil {
		t.Fatal(err)
	}

	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}
