/*
   Copyright 2020 Takahiro Yamashita

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// reference
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

package pecert

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Cert Type
const (
	WIN_CERT_TYPE_X509             = 0x1
	WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x2
	WIN_CERT_TYPE_RESERVED_1       = 0x3
	WIN_CERT_TYPE_TS_STACK_SIGNED  = 0x4
)

const indexOfCertificateTable = 4

// AttributeCertificateHeader represents header of Attribute Certifiates.
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
type AttributeCertificateHeader struct {
	DwLength         uint32
	WRevision        uint16
	WCertificateType uint16
}

func (s AttributeCertificateHeader) String() string {
	return fmt.Sprintf("dwLength:0x%x wRevision:%x wCertificateType:%s(0x%x)",
		s.DwLength, s.WRevision, WCertTypeStr(s.WCertificateType), s.WCertificateType)
}

// AttributeCertificate represents Attribute Certificates.
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
type AttributeCertificate struct {
	AttributeCertificateHeader
	BCertificate []byte
}

// CertTypeStr returns the string of wCertficateType
func WCertTypeStr(c uint16) string {
	switch c {
	case WIN_CERT_TYPE_X509:
		return "WIN_CERT_TYPE_X509"
	case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
		return "WIN_CERT_TYPE_PKCS_SIGNED_DATA"
	case WIN_CERT_TYPE_RESERVED_1:
		return "WIN_CERT_TYPE_RESERVED_1"
	case WIN_CERT_TYPE_TS_STACK_SIGNED:
		return "WIN_CERT_TYPE_TS_STACK_SIGNED"
	}
	return "Unknown"
}

// GetCertTableDirectory returns the Certficate Table Directory from PE file.
func GetCertTableDirectory(f *pe.File) (pe.DataDirectory, error) {
	switch f.OptionalHeader.(type) {
	case (*pe.OptionalHeader32):
		oph := f.OptionalHeader.(*pe.OptionalHeader32)
		return oph.DataDirectory[indexOfCertificateTable], nil
	case (*pe.OptionalHeader64):
		oph := f.OptionalHeader.(*pe.OptionalHeader64)
		return oph.DataDirectory[indexOfCertificateTable], nil
	}
	return pe.DataDirectory{}, fmt.Errorf("DataDirectory not found")
}

func getAttributeCertificatesFromBytes(b []byte, o binary.ByteOrder) ([]AttributeCertificate, error) {
	headersize := 8
	ret := []AttributeCertificate{}

	r := bytes.NewReader(b)

	for r.Len() > headersize /*header size */ {
		var h AttributeCertificateHeader
		if err := binary.Read(r, o, &h); err != nil {
			return ret, fmt.Errorf("binary.Read:%w", err)
		}
		var t AttributeCertificate
		t.AttributeCertificateHeader = h
		certb := make([]byte, t.DwLength-uint32(headersize))
		_, err := r.Read(certb)
		if err != nil {
			return ret, fmt.Errorf("bytes.Read:%w", err)
		} /*else if len(certb) != n {
			return ret, fmt.Errorf("getAttributeCertificatesFromBytes:read size is short :%d, expect:%d", n, len(certb))
		}*/
		t.BCertificate = certb
		ret = append(ret, t)
	}

	return ret, nil
}

func getAttributeCertificates(r io.ReaderAt, pef *pe.File) ([]AttributeCertificate, error) {
	d, err := GetCertTableDirectory(pef)
	if err != nil {
		return []AttributeCertificate{}, nil
	}

	if d.Size == 0 {
		return []AttributeCertificate{}, fmt.Errorf("Certificate Table size is zero")
	}
	b := make([]byte, d.Size)
	n, err := r.ReadAt(b, int64(d.VirtualAddress))
	if n != len(b) {
		return []AttributeCertificate{}, fmt.Errorf("getAttributeCertificates:read size is short :%d", n)
	} else if err != nil {
		return []AttributeCertificate{}, fmt.Errorf("ReadAt:%w", err)
	}

	return getAttributeCertificatesFromBytes(b, binary.LittleEndian /* TODO*/)
}

// GetAttributeCertificates returns AttributeCertificate(s) from r.
func GetAttributeCertificates(r io.ReaderAt) ([]AttributeCertificate, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return []AttributeCertificate{}, nil
	}
	defer f.Close()

	return getAttributeCertificates(r, f)
}

// GetAttributeCertificatesFromPath returns AttributeCertificate(s) from filepath s.
func GetAttributeCertificatesFromPath(s string) ([]AttributeCertificate, error) {
	f, err := os.Open(s)
	if err != nil {
		return []AttributeCertificate{}, fmt.Errorf("os.Open:%w", err)
	}
	defer f.Close()

	pef, err := pe.NewFile(f)
	if err != nil {
		return []AttributeCertificate{}, fmt.Errorf("pe.NewFile:%w", err)
	}
	defer pef.Close()

	return getAttributeCertificates(f, pef)
}
