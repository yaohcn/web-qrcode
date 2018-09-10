package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
)

const qrcode_str = "02010073323038383530323739313630313732385b9b267b02580bb8000000070000000000000000029b35ef58218acc5b7930ad88e63a964b7c269c7462fea158543033333031303010333130303730333130343534373435351c1b0100020000000000000000123456783412000000000000b08e4a03483046022100f75b4e97c2cbfe470e8e3f1b7d16e926b4a0499da0c0a4ea74d98b40b04c4b7d022100b3553ead84f75d0c0bac07a7335e2e17a3e71cec4def657834de56a27c770009045b924ad33730350218260f6e0b928808b4c3f3684e5b54c6daad083953e8dd4dc2021900a0aea55a708edbae20f124f7962840cf6d6597d164b4232c"

type QrcodeInfo struct {
	protoType   string
	sourceId    byte
	version     byte
	algoVersion byte
	keyId       byte
	agencyPuk   [33]byte

	userId           string
	agencyExpTime    [4]byte
	qrcodeEffectTIme [2]byte
	limitAmt         [2]byte
	idInfo           [4]byte
	agencyId         [4]byte
	reserve          [4]byte
	userPuk          [25]byte
	cardType         string
	cardNum          string
	cardData         [64]byte
	qrcodeGeneTime   [4]byte
}

func qrcodeParse(qr []byte, f *QrcodeInfo) {
	var len int
	f.version = qr[len]
	len += 1
	f.algoVersion = qr[len]
	len += 1
	f.keyId = qr[len]
	len += 1
	agencyDataLen := int(qr[len])
	fmt.Println(agencyDataLen)
	len += 1
	f.userId = string(qr[len : len+16])
	len += 16
	copy(f.agencyExpTime[:], qr[len:len+4])
	fmt.Println(f.agencyExpTime)
	b := binary.BigEndian.Uint32(qr[len : len+4])
	fmt.Println(b)
	len += 4
	// f.qrcodeEffectTIme = qr[len : len+2]
	a := binary.BigEndian.Uint16(qr[len : len+2])
	fmt.Printf("%x\n", qr[len:len+2])
	fmt.Println(a)
	len += 2

	fmt.Println(f.userId)
}
func main() {
	var f QrcodeInfo
	fmt.Println(qrcode_str)
	fmt.Println(len(qrcode_str))
	fmt.Println(qrcode_str[0])
	qrcode_hex, err := hex.DecodeString(qrcode_str)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(qrcode_hex))
	qrcode_hex[0] = 0x01
	if qrcode_hex[0] == 0x02 {
		fmt.Println("yes")
	}
	fmt.Printf("%T\t%x\n", qrcode_hex, qrcode_hex)

	qrcodeParse(qrcode_hex, &f)
	fmt.Println(f.userId)
}
