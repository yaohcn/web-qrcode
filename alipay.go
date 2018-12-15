package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

type qrcodeInfo struct {
	ProtoType   string
	SourceId    byte
	Version     byte
	AlgoVersion byte
	KeyId       byte
	AgencyPuk   []byte

	UserId           string
	AgencyExpTime    uint32
	QrcodeEffectTime uint16
	LimitAmt         uint16
	IdInfo           string
	AgencyId         string
	Reserve          []byte
	UserPuk          []byte
	CardType         string
	CardNum          string
	CardData         []byte
	QrcodeGeneTime   uint32

	AgencySigData []byte
	UserSigData   []byte
	AgencySig     []byte
	UserSig       []byte
}
type recordInfo struct {
	RecordVersion byte
	Qrcode        []byte
	TerminalInfo  string
	RecordTime    uint32
	SoftVersion   string
	Sign          bool
	Qr            qrcodeInfo
}

func aliAndOwnRecordParseV1(r []byte, t *recordInfo) error {
	var i int

	t.RecordVersion = r[i] >> 4
	qrcodeLen := (uint16(r[i]&0x0F)<<8 | uint16(r[i+1]))
	i += 2

	t.Qrcode = r[i : i+int(qrcodeLen)]
	i += int(qrcodeLen)
	terminalInfoLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.TerminalInfo = string(r[i : i+terminalInfoLen])
	i += terminalInfoLen

	timeLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.RecordTime = binary.BigEndian.Uint32(r[i : i+timeLen])
	i += timeLen

	message := r[:i]
	signLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	messageMAC := r[i : i+signLen]
	i += signLen

	if len(r) != i {
		return errors.New("record len wrong")
	}
	err := aliAndOwnQrcodeParse(t.Qrcode, &(t.Qr))
	if err != nil {
		return err
	}
	t.Sign = checkMAC(message, messageMAC, []byte(t.Qr.UserId))
	return nil
}
func aliAndOwnRecordParseV2(r []byte, t *recordInfo) error {
	var i int

	t.RecordVersion = r[i] >> 4
	recordLen := (uint16(r[i]&0x0F)<<8 | uint16(r[i+1]))
	i += 2

	if recordLen != uint16(len(r)-2) {
		return errors.New("record len wrong")
	}

	qrcodeLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.Qrcode = r[i : i+qrcodeLen]
	i += qrcodeLen

	terminalInfoLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.TerminalInfo = string(r[i : i+terminalInfoLen])
	i += terminalInfoLen

	timeLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.RecordTime = binary.BigEndian.Uint32(r[i : i+timeLen])
	i += timeLen
	softVersionLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.SoftVersion = string(r[i : i+softVersionLen])
	i += softVersionLen
	message := r[:i]
	signLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	messageMAC := r[i : i+signLen]
	i += signLen

	if recordLen != uint16(i-2) {
		return errors.New("record len wrong")
	}
	err := aliAndOwnQrcodeParse(t.Qrcode, &(t.Qr))
	if err != nil {
		return err
	}
	t.Sign = checkMAC(message, messageMAC, []byte(t.Qr.UserId))
	return nil
}
func aliAndOwnQrcodeParse(qr []byte, f *qrcodeInfo) error {
	if qr[0] == 0x02 {
		f.ProtoType = "支付宝"
		err := aliQrcodeParse(qr, f)
		if err != nil {
			return err
		}
	} else {
		f.ProtoType = "自有码"
		err := aliQrcodeParse(qr[2:], f)
		if err != nil {
			return err
		}
	}
	return nil
}

func aliQrcodeParse(qr []byte, f *qrcodeInfo) error {
	var i int
	f.Version = qr[i]
	i++
	if f.Version != 0x02 {
		return errors.New("original qrcode version is not 0x02")
	}
	f.AlgoVersion = qr[i]
	i++
	f.KeyId = qr[i]
	i++
	agencyDataLen := int(qr[i])
	i++
	if agencyDataLen > len(qr) {
		return errors.New("qrcode len wrong")
	}
	f.UserId = string(qr[i : i+16])
	i += 16
	f.AgencyExpTime = binary.BigEndian.Uint32(qr[i : i+4])
	i += 4
	f.QrcodeEffectTime = binary.BigEndian.Uint16(qr[i : i+2])
	i += 2
	f.LimitAmt = binary.BigEndian.Uint16(qr[i : i+2])
	i += 2
	f.IdInfo = hex.EncodeToString(qr[i : i+4])
	i += 4
	f.AgencyId = hex.EncodeToString(qr[i : i+4])
	i += 4
	f.Reserve = qr[i : i+4]
	i += 4

	f.UserPuk = qr[i : i+25]
	i += 25
	f.CardType = string(qr[i : i+8])
	i += 8
	cardNumLen := int(qr[i])
	i++
	f.CardNum = string(qr[i:(i + cardNumLen)])
	i += cardNumLen
	cardDataLen := int(qr[i])
	i++
	f.CardData = qr[i : i+cardDataLen]
	i += cardDataLen

	f.AgencySigData = qr[4:i]
	if agencyDataLen != (i - 4) {
		return errors.New("agency data len wrong")
	}
	agencySigLen := int(qr[i])
	i++
	f.AgencySig = qr[i : i+agencySigLen]
	i += agencySigLen

	userDataLen := qr[i]
	i++
	if userDataLen != 4 {
		return errors.New("user data len wrong")
	}
	f.QrcodeGeneTime = binary.BigEndian.Uint32(qr[i : i+4])
	i += 4
	f.UserSigData = qr[:i]
	userSigLen := int(qr[i])
	i++
	f.UserSig = qr[i : i+userSigLen]
	i += userSigLen

	if i != len(qr) {
		return errors.New("qrcode len wrong")
	}
	return nil
}

func makeRecord(qr []byte, posParam string, f *qrcodeInfo) string {
	version := "0000.0.20180104"

	tmp := make([]byte, 2)
	tmp1 := make([]byte, 4)

	var b bytes.Buffer

	recordVersion := 2
	recordLen := 2 + len(qr) + 2 + len(posParam) + 2 + 4 + 2 + len(version) + 2 + 16
	var head uint16
	head = uint16(recordVersion)<<12 | uint16(recordLen)
	binary.BigEndian.PutUint16(tmp, head)
	b.Write(tmp)

	binary.BigEndian.PutUint16(tmp, uint16(len(qr)))
	b.Write(tmp)

	b.Write(qr)

	binary.BigEndian.PutUint16(tmp, uint16(len(posParam)))
	b.Write(tmp)
	b.Write([]byte(posParam))

	binary.BigEndian.PutUint16(tmp, uint16(4))
	b.Write(tmp)
	binary.BigEndian.PutUint32(tmp1, f.QrcodeGeneTime+3)
	b.Write(tmp1)

	binary.BigEndian.PutUint16(tmp, uint16(len(version)))
	b.Write(tmp)
	b.Write([]byte(version))

	mac := hmac.New(md5.New, []byte(f.UserId))
	mac.Write(b.Bytes())
	expectedMAC := mac.Sum(nil)

	binary.BigEndian.PutUint16(tmp, uint16(len(expectedMAC)))
	b.Write(tmp)
	b.Write(expectedMAC)

	return hex.EncodeToString(b.Bytes())

}
