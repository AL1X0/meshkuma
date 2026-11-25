package version

import "strings"

// Build-time metadata injected via -ldflags.
var (
	Version   = "v1.0.0"
	Commit    = "dev"
	BuildDate = ""
)

// DefaultUpdateRepo is the GitHub owner/repo checked for newer releases.
const DefaultUpdateRepo = "AL1X0/meshkuma"

// DefaultDockerImage is the public GHCR image used for one-click Docker self-updates.
const DefaultDockerImage = "ghcr.io/al1x0/meshkuma:latest"

// ShortCommit returns up to 7 characters of the build commit SHA.
func ShortCommit() string {
	c := strings.TrimSpace(Commit)
	if len(c) > 7 {
		return c[:7]
	}
	return c
}
