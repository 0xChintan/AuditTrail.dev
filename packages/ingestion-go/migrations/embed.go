// Package migrations embeds the ordered SQL migrations.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
