// Command scheduler is the background job process. It shares the web
// server's Runtime (config, database pool, logger, field cipher) but
// registers no HTTP routes: it only runs the interval jobs in internal/jobs
// (session purging, trash retention, token expiry). Deploy it as its own
// container alongside the web process; see start.sh for the local dev
// wiring.
package main

import (
	"vault3/internal/jobs"
	"vault3/internal/runtime"
)

func main() {
	rt := runtime.StartWorker()
	defer rt.Stop()

	jobs.Run(rt)
}
