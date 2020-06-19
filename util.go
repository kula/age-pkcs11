// Copyright 2020 Thomas L. Kula
// All Rights Reserved
//
// Use of this source code is governed by the license included
// in the LICENSE file

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Given a string like "slot#:token#", return slot and
// token. Both default to 0. Return error if passed something
// not a number
func decode_slot(s string) (int, int, error) {
	if len(s) == 0 {
		// Return defaults
		return 0, 0, nil
	}

	var sliceString, tokenString string
	sSlice := strings.Split(s, ":")
	switch len(sSlice) {
	case 1:
		sliceString = sSlice[0]
		tokenString = "0"
	case 2:
		sliceString = sSlice[0]
		tokenString = sSlice[1]
	default:
		return 0, 0, errors.New("bad slot string")
	}

	slice, err := strconv.Atoi(sliceString)
	if err != nil {
		return 0, 0, fmt.Errorf("Bad slot value: %s", slice)
	}

	token, err := strconv.Atoi(tokenString)
	if err != nil {
		return 0, 0, fmt.Errorf("Bad token value: %s", slice)
	}

	if slice < 0 {
		return 0, 0, fmt.Errorf("Slice cannot be less than 0")
	}

	if token < 0 {
		return 0, 0, fmt.Errorf("Token cannot be less than 0")
	}

	return slice, token, nil
}
