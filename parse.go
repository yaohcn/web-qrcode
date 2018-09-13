package main

import (
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
	Sign          []byte
    Qr qrcodeInfo
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
	signLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.Sign = r[i : i+signLen]
	i += signLen

	if recordLen != uint16(i-2) {
		return errors.New("record len wrong")
	}
    err := aliAndOwnQrcodeParse(t.Qrcode, &(t.Qr))
    if err != nil {
        return err
    }
	return nil
}
func aliAndOwnQrcodeParse(qr []byte, f *qrcodeInfo) error {
    if qr[0] == 0x02 {
        f.ProtoType = "支付宝"
        err := aliQrcodeParse(qr, f)
        if err != nil {
            return err
        }
    }else {
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
	i += 1
	f.AlgoVersion = qr[i]
	i += 1
	f.KeyId = qr[i]
	i += 1
	agencyDataLen := int(qr[i])
	i += 1
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
	i += 1
	f.CardNum = string(qr[i:(i + cardNumLen)])
	i += cardNumLen
	cardDataLen := int(qr[i])
	i += 1
	f.CardData = qr[i : i+cardDataLen]
	i += cardDataLen

	f.AgencySigData = qr[4:i]
	if agencyDataLen != (i - 4) {
		return errors.New("agency data len wrong")
	}
	agencySigLen := int(qr[i])
	i += 1
	f.AgencySig = qr[i : i+agencySigLen]
	i += agencySigLen

	userDataLen := qr[i]
	i += 1
	if userDataLen != 4 {
		return errors.New("user data len wrong")
	}
	f.QrcodeGeneTime = binary.BigEndian.Uint32(qr[i : i+4])
	i += 4
	f.UserSigData = qr[:i]
	userSigLen := int(qr[i])
	i += 1
	f.UserSig = qr[i : i+userSigLen]
	i += userSigLen

	if i != len(qr) {
		return errors.New("qrcode len wrong")
	}
	return nil
}
func aliRecordParseV1(r []byte, t *recordInfo) error {
	var i int

	qrcodeLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.Qrcode = r[i : i+qrcodeLen]
	i += qrcodeLen

	terminalInfoLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.TerminalInfo = string(r[i : i+terminalInfoLen])
	i += terminalInfoLen

	signLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.Sign = r[i : i+signLen]
	i += signLen

	timeLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	t.RecordTime = binary.BigEndian.Uint32(r[i : i+timeLen])
	i += timeLen

	if len(r) != i {
		return errors.New("record len wrong")
	}
    err := aliAndOwnQrcodeParse(t.Qrcode, &(t.Qr))
    if err != nil {
        return err
    }
	return nil
}
