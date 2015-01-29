package w32registry

import (
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/hnakamur/w32syscall"
)

const (
	dwordSize  = 4
	uint16Size = 2
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

func GetValueString(key syscall.Handle, subkey string, valname string) (value string, err error) {
	var bufLen uint32
	subkeyp, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return
	}
	valnamep, err := syscall.UTF16PtrFromString(valname)
	if err != nil {
		return
	}
	var flags uint32 = w32syscall.RRF_RT_REG_SZ
	err = w32syscall.RegGetValue(key, subkeyp, valnamep, flags, nil, nil, &bufLen)
	if err != nil {
		return
	}

	buf := make([]uint16, bufLen)
	err = w32syscall.RegGetValue(key, subkeyp, valnamep, flags, nil, (*byte)(unsafe.Pointer(&buf[0])), &bufLen)
	if err != nil {
		return
	}

	value = syscall.UTF16ToString(buf)
	return
}

func GetValueMultiString(key syscall.Handle, subkey string, valname string) (values []string, err error) {
	var bufLen uint32
	subkeyp, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return
	}
	valnamep, err := syscall.UTF16PtrFromString(valname)
	if err != nil {
		return
	}
	var flags uint32 = w32syscall.RRF_RT_REG_MULTI_SZ
	err = w32syscall.RegGetValue(key, subkeyp, valnamep, flags, nil, nil, &bufLen)
	if err != nil {
		return
	}

	buf := make([]uint16, bufLen)
	err = w32syscall.RegGetValue(key, subkeyp, valnamep, flags, nil, (*byte)(unsafe.Pointer(&buf[0])), &bufLen)
	if err != nil {
		return
	}

	var i int
	for i = 0; i < int(bufLen)-1; i++ {
		if buf[i] == 0 && buf[i+1] == 0 {
			break
		}
	}
	bufStr := string(utf16.Decode(buf[0:i]))
	values = strings.Split(bufStr, "\x00")
	return
}

// GetValueUint32 returns the DWORD value for the specified key, subkey and valname. It sets err to syscall.ERROR_FILE_NOT_FOUND when key, subkey, or valname is not found.
func GetValueUint32(key syscall.Handle, subkey string, valname string) (value uint32, err error) {
	valLen := uint32(dwordSize)
	err = getValue(key, subkey, valname, w32syscall.RRF_RT_REG_DWORD, nil, (*byte)(unsafe.Pointer(&value)), &valLen)
	return
}

func getValue(key syscall.Handle, subkey string, valname string, flags uint32, valtype *uint32, buf *byte, buflen *uint32) error {
	subkeyp, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	valnamep, err := syscall.UTF16PtrFromString(valname)
	if err != nil {
		return err
	}
	return w32syscall.RegGetValue(key, subkeyp, valnamep, flags, valtype, buf, buflen)
}

// SetKeyValueString returns the string value for the specified key, subkey and valname. It sets err to syscall.ERROR_FILE_NOT_FOUND when key, subkey, or valname is not found.
func SetKeyValueString(key syscall.Handle, subkey string, valname string, value string) error {
	var buf []uint16
	buf, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	bufLen := uint32(len(buf) * uint16Size)
	return setKeyValue(key, subkey, valname, syscall.REG_SZ, (*byte)(unsafe.Pointer(&buf[0])), bufLen)
}

func SetKeyValueUint32(key syscall.Handle, subkey string, valname string, value uint32) error {
	valLen := uint32(dwordSize)
	return setKeyValue(key, subkey, valname, syscall.REG_DWORD, (*byte)(unsafe.Pointer(&value)), valLen)
}

func SetKeyValueMultiString(key syscall.Handle, subkey string, valname string, value []string) error {
	multiSz, err := multiSzFromStrings(value)
	if err != nil {
		return err
	}
	bufLen := uint32(len(multiSz) * uint16Size)
	return setKeyValue(key, subkey, valname, syscall.REG_MULTI_SZ, (*byte)(unsafe.Pointer(&multiSz[0])), bufLen)
}

func multiSzFromStrings(values []string) ([]uint16, error) {
	for _, value := range values {
		for i := 0; i < len(value); i++ {
			if value[i] == 0 {
				return nil, syscall.EINVAL
			}
		}
	}
	s := strings.Join(values, "\x00") + "\x00\x00"
	return utf16.Encode([]rune(s)), nil
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
