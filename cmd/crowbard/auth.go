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

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

type localUser struct {
	username string
	password string
}

type User interface {
	Authenticate(nonce []byte, hmac []byte) bool
	GetPassword() string
}

func (u localUser) Authenticate(nonce []byte, givenMac []byte) bool {
	mac := hmac.New(sha256.New, []byte(u.password))
	mac.Write(nonce)
	expectedMac := mac.Sum(nil)
	return hmac.Equal(expectedMac, givenMac)
}

func (u localUser) GetPassword() string {
	return u.password
}

var userMap = map[string]User{}

func UserGet(username string) (User, bool) {
	val, ok := userMap[username]

	return val, ok
}

/*
func UserGetPassword(username string) (string, bool) {
	val, ok := userMap[username]

	if !ok {
		return "", false
	}

	if lu, ok1 := val.(localUser); ok1 {
		return lu.password, ok1

	}

	return "", false
}
*/

func loadUsersFromFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open user file: %s\n", err)
		return
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Count(line, ":") != 1 {
			fmt.Fprintf(os.Stderr, "Invalid userfile line: %s\n", line)
			continue
		}
		parts := strings.Split(line, ":")

		user := localUser{username: parts[0], password: parts[1]}
		fmt.Fprintf(os.Stderr, "Loaded user %s\n", user.username)
		userMap[user.username] = user
	}
}
