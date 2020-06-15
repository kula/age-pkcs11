// +build 386 amd64

// Copyright 2020 Thomas L. Kula
// All Rights Reserved
//
// Use of this source code is governed by the license included
// in the LICENSE file

package main

import (
    "encoding/binary"
    "errors"
    "math"
)

// Given an integer, return a byte array representing the integer
func itoba(n int) ([]byte, error) {

    if n < 0 {
	return nil, errors.New("Cannot have a negative number")
    }

    if n <= math.MaxUint8 {
	b := make([]byte, 1)
	b[0] = byte(n)
	return b, nil
    } else if n <= math.MaxUint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(n))
	return b, nil
    } else if n <= math.MaxUint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(n))
	return b, nil
    } else {
	return nil, errors.New("Number too large")
    }
}
