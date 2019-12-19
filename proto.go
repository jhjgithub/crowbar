// Copyright (c) 2015, Segiusz 'q3k' Bazanski <sergiusz@bazanski.pl>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package crowbar

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

const PrefixError string = "ERROR:"
const PrefixOK string = "OK:"
const PrefixData string = "DATA:"
const PrefixQuit string = "QUIT:"

func WriteHTTPError(w http.ResponseWriter, message string) {
	body := fmt.Sprintf("%s%s", PrefixError, message)
	http.Error(w, body, http.StatusInternalServerError)
}

func WriteHTTPOK(w http.ResponseWriter, data string) {
	fmt.Fprintf(w, "%s%s", PrefixOK, data)
}

func WriteHTTPData(w http.ResponseWriter, data []byte) {
	data_encoded := base64.StdEncoding.EncodeToString(data)
	fmt.Fprintf(w, "%s%s", PrefixData, data_encoded)
}

func WriteEncryptedHTTPData(w http.ResponseWriter, aeskey []byte, data []byte) {
	// encrypt(key, data)
	data_encoded, err := EncryptAES(aeskey, string(data))
	if err != nil {
		return
	}

	fmt.Fprintf(w, "%s%s", PrefixData, data_encoded)
}

func WriteHTTPQuit(w http.ResponseWriter, data string) {
	fmt.Fprintf(w, "%s%s", PrefixQuit, data)
}

const EndpointConnect string = "/connect/"
const EndpointSync string = "/sync/"
const EndpointAuth string = "/auth/"
