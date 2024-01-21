//go:build ignoreunix
// +build ignoreunix

package main

import (
	"syscall/js"

	"github.com/hiddify/ray2sing/ray2sing"
)

func main() {
	c := make(chan struct{}, 0)

	// Expose the function to JavaScript
	js.Global().Set("callGoFunction", js.FuncOf(callGoFunction))

	<-c
}

func callGoFunction(this js.Value, args []js.Value) (string, error) {
	input := args[0].String()

	// Process the input and generate output
	output, err := ray2sing.Ray2Singbox(input)

	return output, err
}
