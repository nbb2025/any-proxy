package version

// Version identifies the agent/build semantic version.
var Version = "dev"

// Commit describes the git commit associated with the build.
var Commit = ""

// BuildTime optionally stores the build timestamp.
var BuildTime = ""

// Summary returns a human readable version description.
func Summary() string {
	if Commit == "" {
		return Version
	}
	return Version + "+" + Commit
}
