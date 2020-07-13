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

package main

import (
	"fmt"
	"github.com/nokute78/pe-cert-reader/pkg/pecert"
	"io"
	"io/ioutil"
)

func dumpCertToFile(o io.Writer, cert []byte, path string, i int) error {
	certp := fmt.Sprintf("%s.cert%d", path, i)
	err := ioutil.WriteFile(certp, cert, 0644)
	if err != nil {
		return err
	}
	fmt.Fprintf(o, "   dump cert as \"%s\"\n", certp)
	fmt.Fprintf(o, "   e.g. openssl pkcs7 -in %s -inform der\n", certp)
	return nil
}

func readCert(o io.Writer, paths []string, dump bool) error {
	for _, path := range paths {
		fmt.Fprintf(o, "%s:\n", path)
		acs, err := pecert.GetAttributeCertificatesFromPath(path)
		if err != nil {
			return err
		}

		for i, ac := range acs {
			fmt.Fprintf(o, " cert%d: %s\n", i, ac.AttributeCertificateHeader)
			if dump {
				err = dumpCertToFile(o, ac.BCertificate, path, i)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
