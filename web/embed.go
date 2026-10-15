// Package web holds the browser helper served at /v1/passkey-auth.js.
package web

import _ "embed"

// Version of the helper, logged with each load as a usage metric.
const Version = "1"

// Helper is the ES module source of the browser helper.
//
//go:embed passkey-auth.js
var Helper []byte

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | embeds the browser helper                                     |
