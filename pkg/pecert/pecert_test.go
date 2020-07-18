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

package pecert

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func createAttributeCert(t *testing.T, body []byte) *AttributeCertificate {
	t.Helper()
	h := AttributeCertificateHeader{DwLength: uint32(8 + len(body)), WRevision: 0x0200, WCertificateType: WIN_CERT_TYPE_PKCS_SIGNED_DATA}
	return &AttributeCertificate{AttributeCertificateHeader: h, BCertificate: body}
}

func TestMultipleCert(t *testing.T) {
	border := binary.LittleEndian
	bodys := [][]byte{[]byte{0xaa, 0xbb, 0xcc}, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}}
	certs := []*AttributeCertificate{}
	for _, v := range bodys {
		certs = append(certs, createAttributeCert(t, v))
	}

	buffer := bytes.NewBuffer([]byte{})

	for _, v := range certs {
		if err := binary.Write(buffer, border, v.AttributeCertificateHeader); err != nil {
			t.Fatalf("1st binary.Write:%s", err)
		}
		_, err := buffer.Write(v.BCertificate)
		if err != nil {
			t.Fatalf("1st buffer.Write:%s", err)
		}
		for i := 0; i < 8-len(v.BCertificate); i++ {
			if err := buffer.WriteByte(0x00); err != nil {
				t.Fatalf("buffer.WriteByte:%s", err)
			}
		}
	}
	rets, err := getAttributeCertificatesFromBytes(buffer.Bytes(), border)
	if err != nil {
		t.Fatalf("%s", err)
	}

	if len(rets) != len(certs) {
		t.Fatalf("length error. given:%d expect:%d", len(rets), len(certs))
	}
	for i, ret := range rets {
		if ret.AttributeCertificateHeader != certs[i].AttributeCertificateHeader {
			t.Fatalf("mismatch:given %v, expect %v", ret, certs[i])
		}
		if bytes.Compare(ret.BCertificate, certs[i].BCertificate) != 0 {
			t.Fatalf("mismatch cert:given %v, expect %v", ret, certs[i])
		}
	}

}

func TestWCertTypeStr(t *testing.T) {
	type testcase struct {
		input  uint16
		expect string
	}

	cases := []testcase{
		{0x1, "WIN_CERT_TYPE_X509"},
		{0x2, "WIN_CERT_TYPE_PKCS_SIGNED_DATA"},
		{0x3, "WIN_CERT_TYPE_RESERVED_1"},
		{0x4, "WIN_CERT_TYPE_TS_STACK_SIGNED"},
		{0xff, "Unknown"},
	}

	for _, v := range cases {
		ret := WCertTypeStr(v.input)
		if ret != v.expect {
			t.Errorf("\ngiven :%s\nexpect:%s", ret, v.expect)
		}
	}

}
