package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
    "errors"
    "time"
)

const qrcode_str = "02010073323038383530323739313630313732385b9b267b02580bb8000000070000000000000000029b35ef58218acc5b7930ad88e63a964b7c269c7462fea158543033333031303010333130303730333130343534373435351c1b0100020000000000000000123456783412000000000000b08e4a03483046022100f75b4e97c2cbfe470e8e3f1b7d16e926b4a0499da0c0a4ea74d98b40b04c4b7d022100b3553ead84f75d0c0bac07a7335e2e17a3e71cec4def657834de56a27c770009045b924ad33730350218260f6e0b928808b4c3f3684e5b54c6daad083953e8dd4dc2021900a0aea55a708edbae20f124f7962840cf6d6597d164b4232c"
const record_str = "215e00df02010057323038383432323435383332333334305b9618ab025807d0000000660000000000000000038af6c2833d8057170566bb167dd66f5e558c7e462ff569c65430333230353030103231353030303030303032383639383100473045022005c10deadfb29f5ea7c2970609e6191b3cfb4bfeee47964a0584af636bbd8cb9022100f2daaaff03614619e77dc963f145ca36a72f197bbbd5913ed452b4892762887c045b8ce4f536303402187ce7d67547f409d9bd630479a317c64ca3d066c879e09d7d02185b53aa6b844dd3de8c6bc685f5e547c50adc38487bb2faf200577b22706f735f6964223a22222c2274797065223a2253494e474c45222c227375626a656374223a22303030303031222c227265636f72645f6964223a225f32303138303930333135333930325f3030303138373732227d00045b8ce516000a45312e353138303832390010dc4d53bbc5283406a0888c2b7effdd21"

type QrcodeInfo struct {
	protoType   string
	sourceId    byte
	version     byte
	aigoVersion byte
	keyId       byte
	agencyPuk   []byte

	userId           string
	agencyExpTime    uint32
	qrcodeEffectTIme uint16
	iimitAmt         uint16
	idInfo           string
	agencyId         string
	reserve          []byte
	userPuk          []byte
	cardType         string
	cardNum          string
	cardData         []byte
	qrcodeGeneTime   uint32

	agencySigData []byte
	userSigData   []byte
	agencySig     []byte
	userSig       []byte
}
type RecordInfo struct {
   recordVersion byte
   qrcode []byte
   terminalInfo string
   recordTime uint32
   softVersion string
   sign []byte
}
func recordParse(r []byte, t *RecordInfo) error{
    var i int

    t.recordVersion = r[i] >> 4
    recordLen := (uint16(r[i] & 0x0F)<<8 | uint16(r[i+1]))
    i += 2

    qrcodeLen := int(binary.BigEndian.Uint16(r[i:i+2]))
    i += 2;
    t.qrcode = r[i:i+qrcodeLen]
    i += qrcodeLen

    terminalInfoLen := int(binary.BigEndian.Uint16(r[i:i+2]))
    i += 2
    t.terminalInfo = string(r[i:i+terminalInfoLen])
    i += terminalInfoLen

    timeLen := int(binary.BigEndian.Uint16(r[i:i+2]))
    i += 2
    t.recordTime = binary.BigEndian.Uint32(r[i:i+timeLen])
    fmt.Printf("%x\n", r[i:i+4])
    i += timeLen
    softVersionLen := int(binary.BigEndian.Uint16(r[i:i+2]))
    i += 2
    t.softVersion = string(r[i:i+softVersionLen])
    i += softVersionLen
    signLen := int(binary.BigEndian.Uint16(r[i:i+2]))
    i += 2
    t.sign = r[i:i+signLen]
    fmt.Printf("sign:%x\n", t.sign)
    fmt.Println(t.softVersion)


    fmt.Println(t.recordTime)
    fmt.Println(time.Unix(int64(t.recordTime), 0).Format("2006-01-02 15:04:05"))


    fmt.Println(recordLen)
    fmt.Println(t.terminalInfo)
    return nil
}
func qrcodeParse(qr []byte, f *QrcodeInfo) error{
	var i int
	f.version = qr[i]
	i += 1
	f.aigoVersion = qr[i]
	i += 1
	f.keyId = qr[i]
	i += 1
	agencyDataLen := int(qr[i])
	fmt.Println(agencyDataLen)
	i += 1
	f.userId = string(qr[i : i+16])
	i += 16
	f.agencyExpTime = binary.BigEndian.Uint32(qr[i : i+4])
	i += 4
	f.qrcodeEffectTIme = binary.BigEndian.Uint16(qr[i : i+2])
	i += 2
	f.iimitAmt = binary.BigEndian.Uint16(qr[i : i+2])
	i += 2
	f.idInfo = hex.EncodeToString(qr[i : i+4])
	i += 4
	f.agencyId = hex.EncodeToString(qr[i : i+4])
	i += 4
	f.reserve = qr[i : i+4]
	i += 4

	f.userPuk = qr[i : i+25]
	fmt.Printf("userPuk:%x\n", f.userPuk)
	i += 25
	f.cardType = string(qr[i : i+8])
	i += 8
	cardNumLen := int(qr[i])
	i += 1
	f.cardNum = string(qr[i:(i + cardNumLen)])
	i += cardNumLen
	cardDataLen := int(qr[i])
	i += 1
	f.cardData = qr[i : i+cardDataLen]
	i += cardDataLen

	f.agencySigData = qr[4:i]
	fmt.Printf("agencySigData:%x\n", f.agencySigData)
	if agencyDataLen != (i - 4) {
		return errors.New("agency data len wrong")
	}
	agencySigLen := int(qr[i])
	i += 1
	f.agencySig = qr[i : i+agencySigLen]
	i += agencySigLen
	fmt.Printf("agencySig:%x\n", f.agencySig)

	userDataLen := qr[i]
	i += 1
	if userDataLen != 4 {
		return errors.New("user data len wrong")
	}
	f.qrcodeGeneTime = binary.BigEndian.Uint32(qr[i : i+4])
	i += 4
	f.userSigData = qr[:i]
	fmt.Printf("userSigData:%x\n", f.userSigData)
	userSigLen := int(qr[i])
	i += 1
	f.userSig = qr[i : i+userSigLen]
	i += userSigLen
	fmt.Printf("userSig:%x\n", f.userSig)

	if i != len(qr) {
		return errors.New("qrcode len wrong")
	}
    return nil;
}
func qrcodeParseTest() {
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
    fmt.Println(f.agencyId)
}
func recordParseTest() {
	var f RecordInfo
	record_hex, err := hex.DecodeString(record_str)
	if err != nil {
		log.Fatal(err)
	}
	recordParse(record_hex, &f)
}
func main() {
    //qrcodeParseTest();
    recordParseTest()
}
