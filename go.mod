module proxycheck

go 1.24.0

replace golang.org/x/sys => github.com/golang/sys v0.20.0

replace golang.org/x/text => github.com/golang/text v0.20.0

replace golang.org/x/net => github.com/golang/net v0.20.0

require (
	github.com/tailscale/walk v0.0.0-20260702185836-28b80ea70d3b
	github.com/tailscale/win v0.0.0-20260619195133-2d76c33a64c1
	golang.org/x/crypto v0.18.0
	golang.org/x/net v0.35.0
	golang.org/x/text v0.22.0
)

require (
	github.com/dblohm7/wingoes v0.0.0-20231019175336-f6e33aa7cc34 // indirect
	golang.org/x/exp v0.0.0-20230425010034-47ecfdc1ba53 // indirect
	golang.org/x/sys v0.37.0 // indirect
	gopkg.in/Knetic/govaluate.v3 v3.0.0 // indirect
)

replace golang.org/x/crypto => github.com/golang/crypto v0.20.0

replace golang.org/x/exp => github.com/golang/exp v0.0.0-20230425010034-47ecfdc1ba53

replace gopkg.in/Knetic/govaluate.v3 => github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
