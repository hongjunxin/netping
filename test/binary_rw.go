package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

type UserData struct {
	Kind       int8
	_          int8 // binary.Read/Write() include padding
	Type       int16
	Seq        int16
	DstSendCnt int16
	DstRecvCnt int16
	ProcTime   int32 // peer process time
	_          int8
	_          int8
	SendTs     int64
}

func main() {
	ud := UserData{
		Kind:       1,
		Type:       10086,
		Seq:        6920,
		DstSendCnt: 1,
		DstRecvCnt: 2,
		ProcTime:   3,
		SendTs:     1646219593348,
	}

	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.BigEndian, ud); err != nil {
		fmt.Printf("binary.Write() failed, err=%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("buf size: %v\n", buf.Len())

	ud2 := UserData{}
	if err := binary.Read(buf, binary.BigEndian, &ud2); err != nil {
		fmt.Printf("binary.Read() failed, err=%v\n", err)
		os.Exit(1)
	}
	if ud != ud2 {
		fmt.Println("tanslate failed")
		fmt.Printf("ud:  %v\n", ud)
		fmt.Printf("ud2: %v\n", ud2)
	}

	fmt.Println("translate succeed")
	fmt.Printf("ud:  %v\n", ud)
	fmt.Printf("ud2: %v\n", ud2)
}
