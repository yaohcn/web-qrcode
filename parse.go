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
type motQrcodeInfo struct {
}
type motRecordInfo struct {
	Version         byte
	Qrcode          []byte
	PosMfId         string
	PosId           string
	PosSwVersion    string
	RecordId        string
	MerchantType    string
	ConsumptionType byte
	Currency        string
	Amount          uint32
	VehicleId       string
	PlateNo         string
	DriverId        string
	LineInfo        string
	StationNo       string
	LbsInfo         string
	RecordTime      uint32
	Sign            bool

	Qr motQrcodeInfo
}

func motRecordParse(r []byte, t *motRecordInfo) error {
	return nil
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
		return errors.New("record len wrong22")
	}
	err := aliAndOwnQrcodeParse(t.Qrcode, &(t.Qr))
	if err != nil {
		return err
	}
	t.Sign = checkMD5(message, messageMAC)
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
func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(md5.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
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

//利用bytes.buffer重构aliQrcodeParse
func aliQrcodeParse2(qr []byte, f *qrcodeInfo) error {
	var err error
	buf := bytes.NewBuffer(qr)
	f.Version, err = buf.ReadByte()
	if err != nil {
		return errors.New("ReadByte error!")
	}
	if f.Version != 0x02 {
		return errors.New("original qrcode version is not 0x02")
	}
	f.AlgoVersion, err = buf.ReadByte()
	if err != nil {
		return errors.New("ReadByte error!")
	}
	f.KeyId, err = buf.ReadByte()
	if err != nil {
		return errors.New("ReadByte error!")
	}
	agencyDataLen, err := buf.ReadByte()
	if err != nil {
		return errors.New("ReadByte error!")
	}
	if int(agencyDataLen) > len(qr) {
		return errors.New("qrcode len wrong")
	}
	f.UserId = string(buf.Next(16))
	f.AgencyExpTime = binary.BigEndian.Uint32(buf.Next(4))
	f.QrcodeEffectTime = binary.BigEndian.Uint16(buf.Next(2))
	f.LimitAmt = binary.BigEndian.Uint16(buf.Next(2))
	f.IdInfo = hex.EncodeToString(buf.Next(4))
	f.AgencyId = hex.EncodeToString(buf.Next(4))
	f.Reserve = buf.Next(4)

	f.UserPuk = buf.Next(25)
	f.CardType = string(buf.Next(8))
	cardNumLen, err := buf.ReadByte()
	if err != nil {
		return errors.New("ReadByte error!")
	}
	f.CardNum = string(buf.Next(int(cardNumLen)))
	cardDataLen, err := buf.ReadByte()
	if err != nil {
		return errors.New("ReadByte error!")
	}
	f.CardData = buf.Next(int(cardDataLen))

	agencySigLen, err := buf.ReadByte()
	if err != nil {
		return errors.New("ReadByte error!")
	}
	f.AgencySig = buf.Next(int(agencySigLen))

	userDataLen, err := buf.ReadByte()
	if err != nil {
		return errors.New("ReadByte error!")
	}
	if int(userDataLen) != 4 {
		return errors.New("user data len wrong")
	}
	f.QrcodeGeneTime = binary.BigEndian.Uint32(buf.Next(4))
	userSigLen, err := buf.ReadByte()
	if err != nil {
		return errors.New("ReadByte error!")
	}
	f.UserSig = buf.Next(int(userSigLen))

	return nil
}
func aliQrcodeParse(qr []byte, f *qrcodeInfo) error {
	var i int
	f.Version = qr[i]
	i += 1
	if f.Version != 0x02 {
		return errors.New("original qrcode version is not 0x02")
	}
	f.AlgoVersion = qr[i]
	i += 1
	f.KeyId = qr[i]
	i += 1
	agencyDataLen := int(qr[i])
	i += 1
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

	message := r[:i]
	signLen := int(binary.BigEndian.Uint16(r[i : i+2]))
	i += 2
	messageMAC := r[i : i+signLen]
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
	t.Sign = checkMD5(message, messageMAC)
	return nil
}
func checkMD5(message, messageMAC []byte) bool {
	mac := md5.New()
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	i := bytes.Compare(messageMAC, expectedMAC)
	if i == 0 {
		return true
	}
	return false
}
