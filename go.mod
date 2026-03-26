module github.com/loudmumble/sentinel

go 1.24.2

require (
	github.com/loudmumble/syscalld v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.9
	golang.org/x/sys v0.38.0
)

// NOTE: Once syscalld is tagged on GitHub, replace this with a proper version.
// For local development: replace github.com/loudmumble/syscalld => ../syscalld
replace github.com/loudmumble/syscalld => github.com/loudmumble/syscalld v0.1.0

require (
	github.com/cilium/ebpf v0.17.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
)
