package main

import (
	_ "embed"
	"syscall/js"
)

func main() {
	c := make(chan struct{}, 0)

	js.Global().Set("callGoFunction", js.FuncOf(callGoFunction))

	<-c
}

func callGoFunction(this js.Value, args []js.Value) interface{} {
	// Your function logic here
	result := "Hello from Go!"
	return js.ValueOf(result)
}
