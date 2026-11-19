package app

import (
	"proxycheck/internal/engine"
	"proxycheck/internal/node"
)

type engineResult struct {
	n     node.Node
	alive bool
}

func toEngine(in []engineResult) []engine.Result {
	var out []engine.Result
	for _, r := range in {
		out = append(out, engine.Result{Node: r.n, Alive: r.alive})
	}
	return out
}
