// Command audittrail-healthcheck is a container health probe for images
// without a shell or curl: it exits 0 if the URL answers 2xx. Only plain
// http to a loopback address is accepted: it probes its own container.
//
//	audittrail-healthcheck http://127.0.0.1:8080/healthz
package main

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	target := "http://127.0.0.1:8080/healthz"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" {
		os.Exit(2)
	}
	if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
		os.Exit(2)
	}
	res, err := (&http.Client{Timeout: 3 * time.Second}).Get(u.String()) // #nosec G107 G704 -- loopback-only, checked above
	if err != nil {
		os.Exit(1)
	}
	res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		os.Exit(1)
	}
}
