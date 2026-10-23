package registry

import "time"

// SetTimeouts shortens the request and lookup budgets for tests.
func SetTimeouts(c *Client, request, lookup time.Duration) {
	if request > 0 {
		c.requestTimeout = request
	}
	if lookup > 0 {
		c.lookupTimeout = lookup
	}
}
