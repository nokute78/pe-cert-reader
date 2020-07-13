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
	"testing"
)

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
