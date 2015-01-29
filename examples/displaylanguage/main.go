package main

import (
	"fmt"
	"syscall"

	"github.com/hnakamur/w32registry"
)

func main() {
	err := w32registry.SetKeyValueMultiString(syscall.HKEY_CURRENT_USER, `Control Panel\Desktop`, "PreferredUILanguagesPending", []string{"ja-JP"})
	if err != nil {
		panic(err)
	}

	values, err := w32registry.GetValueMultiString(syscall.HKEY_CURRENT_USER, `Control Panel\Desktop`, "PreferredUILanguagesPending")
	if err != nil {
		panic(err)
	}
	for _, value := range values {
		fmt.Printf("value=%s.\n", value)
	}
}
