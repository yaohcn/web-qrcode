package main

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type pukCA struct {
	Head           byte
	ServiceMark    []byte
	CaIndex        byte
	CaFormat       byte
	CardIssuerMark []byte
	FailDate       []byte
	SerialNo       []byte
	SignMark       byte
	CryptoMark     byte
	PukParamMark   byte
	PukLen         byte
	PubKey         []byte
	Sign           []byte
}
type motQrcode struct {
	Version          byte
	CardPukCA        []byte
	PayAccountNo     string
	UserAccountNo    []byte
	CardIssuerNo     []byte
	CodeIssuerNo     []byte
	UserAccountType  byte
	LimitAmt         uint32
	UserPuk          []byte
	AuthorizeTime    uint32
	QrcodeEffectTime uint16
	QrcodeGeneTime   uint32
	Customize        []byte
	IssuerSign       []byte
	UserSign         []byte

	Puk pukCA
}
type motRecord struct {
	ProtoType       string
	Version         []byte
	Qrcode          []byte
	PosMfId         string
	PosId           string
	PosSwVersion    string
	RecordId        string
	MerchantType    string
	ConsumptionType []byte
	Currency        string
	Amount          uint32
	VehicleId       string
	PlateNo         string
	DriverId        string
	LineInfo        string
	StationNo       string
	LbsInfo         string
	RecordTime      uint32
	Sign            []byte
	RecordType      string

	MotQr motQrcode
	AliQr qrcodeInfo
}

func pukParse(puk []byte, p *pukCA) error {
	var err error
	if len(puk) != 117 {
		return errors.New("puk ca len wrong(not 117)")
	}
	buf := bytes.NewBuffer(puk)
	p.Head, err = buf.ReadByte()
	if err != nil {
		return err
	}
	p.ServiceMark = buf.Next(4)
	p.CaIndex, err = buf.ReadByte()
	if err != nil {
		return err
	}
	p.CaFormat, err = buf.ReadByte()
	if err != nil {
		return err
	}
	p.CardIssuerMark = buf.Next(4)
	p.FailDate = buf.Next(2)
	p.SerialNo = buf.Next(3)
	p.SignMark, err = buf.ReadByte()
	if err != nil {
		return err
	}
	p.CryptoMark, err = buf.ReadByte()
	if err != nil {
		return err
	}
	p.PukParamMark, err = buf.ReadByte()
	if err != nil {
		return err
	}
	p.PukLen, err = buf.ReadByte()
	if err != nil {
		return err
	}
	p.PubKey = buf.Next(33)
	p.Sign = buf.Next(64)

	return nil
}
func motQrcodeParse(qr []byte, m *motQrcode) error {
	var err error
	buf := bytes.NewBuffer(qr)
	m.Version, err = buf.ReadByte()
	if err != nil {
		return err
	}
	tmp := binary.BigEndian.Uint16(buf.Next(2))
	if int(tmp)+1+2 != len(qr) {
		return errors.New("qrcode len wrong")
	}
	m.CardPukCA = buf.Next(117)
	m.PayAccountNo = string(buf.Next(16))
	m.UserAccountNo = buf.Next(10)
	m.CardIssuerNo = buf.Next(4)
	m.CodeIssuerNo = buf.Next(4)
	m.UserAccountType, err = buf.ReadByte()
	if err != nil {
		return err
	}
	b := buf.Next(3)
	m.LimitAmt = uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
	m.UserPuk = buf.Next(33)
	m.AuthorizeTime = binary.BigEndian.Uint32(buf.Next(4))
	m.QrcodeEffectTime = binary.BigEndian.Uint16(buf.Next(2))
	l, err := buf.ReadByte()
	if err != nil {
		return err
	}
	if l != 0 {
		m.Customize = buf.Next(int(l))
	}
	m.IssuerSign = buf.Next(65)
	m.QrcodeGeneTime = binary.BigEndian.Uint32(buf.Next(4))
	m.UserSign = buf.Next(65)

	err = pukParse(m.CardPukCA, &(m.Puk))
	if err != nil {
		return err
	}

	return nil
}
func motRecordParse(r []byte, m *motRecord) error {
	var err error
	buf := bytes.NewBuffer(r)

	for buf.Len() != 0 {
		t := buf.Next(2)
		l := binary.BigEndian.Uint16(buf.Next(2))
		v := buf.Next(int(l))
		switch {
		case bytes.Compare([]byte("\x00\x00"), t) == 0:
			m.Version = v
		case bytes.Compare([]byte("\x00\x01"), t) == 0:
			m.Qrcode = v
		case bytes.Compare([]byte("\x00\x02"), t) == 0:
			m.PosMfId = string(v)
		case bytes.Compare([]byte("\x00\x03"), t) == 0:
			m.PosId = string(v)
		case bytes.Compare([]byte("\x00\x04"), t) == 0:
			m.PosSwVersion = string(v)
		case bytes.Compare([]byte("\x00\x05"), t) == 0:
			m.RecordId = string(v)
		case bytes.Compare([]byte("\x00\x06"), t) == 0:
			m.MerchantType = string(v)
		case bytes.Compare([]byte("\x00\x07"), t) == 0:
			m.ConsumptionType = v
		case bytes.Compare([]byte("\x00\x08"), t) == 0:
			m.Currency = string(v)
		case bytes.Compare([]byte("\x00\x09"), t) == 0:
			if l == 2 {
				m.Amount = uint32(v[1]) | uint32(v[0])<<8
			} else if l == 3 {
				m.Amount = uint32(v[2]) | uint32(v[1])<<8 | uint32(v[0])<<16
			} else if l == 1 {
				m.Amount = uint32(v[0])
			} else if l == 4 {
				m.Amount = uint32(v[3]) | uint32(v[2])<<8 | uint32(v[1])<<16 | uint32(v[0])<<24
			}
		case bytes.Compare([]byte("\x00\x0A"), t) == 0:
			m.VehicleId = string(v)
		case bytes.Compare([]byte("\x00\x0B"), t) == 0:
			m.PlateNo = string(v)
		case bytes.Compare([]byte("\x00\x0C"), t) == 0:
			m.DriverId = string(v)
		case bytes.Compare([]byte("\x00\x0D"), t) == 0:
			m.LineInfo = string(v)
		case bytes.Compare([]byte("\x00\x0E"), t) == 0:
			m.StationNo = string(v)
		case bytes.Compare([]byte("\x00\x0F"), t) == 0:
			m.LbsInfo = string(v)
		case bytes.Compare([]byte("\x00\x10"), t) == 0:
			if l != 4 {
				return errors.New("record time len not 4")
			}
			m.RecordTime = binary.BigEndian.Uint32(v)
		case bytes.Compare([]byte("\x00\x11"), t) == 0:
			m.Sign = v
		case bytes.Compare([]byte("\x00\x12"), t) == 0:
			m.RecordType = string(v)
		default:
			return errors.New("tag not support")
		}
	}
	if m.Qrcode[0] == 0x02 {
		m.ProtoType = "支付宝"
		err := aliQrcodeParse(m.Qrcode, &(m.AliQr))
		if err != nil {
			return err
		}
	} else if m.Qrcode[0] >= 0x80 {
		m.ProtoType = "交通部"
		err = motQrcodeParse(m.Qrcode, &(m.MotQr))
		if err != nil {
			return err
		}
	}

	return nil
}
