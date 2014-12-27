package w32registry

import (
	"syscall"
	"unsafe"

	"github.com/hnakamur/w32syscall"
)

func CreateKey(key syscall.Handle, subkey string, class string, options uint32, desiredAccess uint32, securityAttributes *syscall.SecurityAttributes, disposition *uint32) (result syscall.Handle, err error) {
	var (
		subkeyp, classp *uint16
		reserved        uint32
	)
	if len(subkey) > 0 {
		subkeyp, err = syscall.UTF16PtrFromString(subkey)
		if err != nil {
			return
		}
	}
	if len(class) > 0 {
		classp, err = syscall.UTF16PtrFromString(class)
		if err != nil {
			return
		}
	}
	err = w32syscall.RegCreateKeyEx(key, subkeyp, reserved, classp, options, desiredAccess, securityAttributes, &result, disposition)
	return
}

func DeleteKeyValue(key syscall.Handle, subkey string, valname string) error {
	var (
		subkeyp, valnamep *uint16
		err               error
	)
	if len(subkey) > 0 {
		subkeyp, err = syscall.UTF16PtrFromString(subkey)
		if err != nil {
			return err
		}
	}
	if len(valname) > 0 {
		valnamep, err = syscall.UTF16PtrFromString(valname)
		if err != nil {
			return err
		}
	}
	return w32syscall.RegDeleteKeyValue(key, subkeyp, valnamep)
}

func DeleteTree(key syscall.Handle, subkey string) error {
	var (
		subkeyp *uint16
		err     error
	)
	if len(subkey) > 0 {
		subkeyp, err = syscall.UTF16PtrFromString(subkey)
		if err != nil {
			return err
		}
	}
	return w32syscall.RegDeleteTree(key, subkeyp)
}

func SetKeyValueString(key syscall.Handle, subkey string, valname string, value string) error {
	var buf []uint16
	buf, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	bufLen := uint32(len(buf) + 2) // 2 for the terminating null character
	return setKeyValue(key, subkey, valname, syscall.REG_SZ, (*byte)(unsafe.Pointer(&buf[0])), bufLen)
}

func SetKeyValueUint32(key syscall.Handle, subkey string, valname string, value uint32) error {
	valLen := uint32(4) // uint32 size in bytes
	return setKeyValue(key, subkey, valname, syscall.REG_DWORD, (*byte)(unsafe.Pointer(&value)), valLen)
}

func setKeyValue(key syscall.Handle, subkey string, valname string, valtype uint32, buf *byte, buflen uint32) error {
	subkeyp, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	valnamep, err := syscall.UTF16PtrFromString(valname)
	if err != nil {
		return err
	}
	return w32syscall.RegSetKeyValue(key, subkeyp, valnamep, valtype, buf, buflen)
}
