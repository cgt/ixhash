// Package ixhash implements the iXhash fuzzy e-mail hashing algorithms
// and provides facilities for checking iXhash digests against DNS lists.
package ixhash // import "cgt.name/pkg/ixhash"

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"net"
	"regexp"
	"unicode"
)

// Apparently the unicode package and PCRE disagree on what constitutes a
// graph or print symbol.
var (
	graphPCRE = []*unicode.RangeTable{
		unicode.L,
		unicode.M,
		unicode.N,
		unicode.P,
		unicode.S,
		unicode.Cf,
	}

	printPCRE = []*unicode.RangeTable{
		unicode.L,
		unicode.M,
		unicode.N,
		unicode.P,
		unicode.S,
		unicode.Cf,
		unicode.Zs,
	}
)

// md5hash calculates the md5 hash of a byte slice and returns a hex digest.
func md5hash(b []byte) string {
	h := md5.New()
	h.Write(b)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// squeezeSpaces squeezes multiple duplicate spaces in a row to a single space
// character. Like: $ tr -s '[:space:]'
func squeezeSpaces(s []byte) []byte {
	buf := make([]byte, 0, len(s))
	prev := s[0]
	buf = append(buf, prev)
	for i := 1; i < len(s); i++ {
		b := s[i]
		issp := unicode.IsSpace(rune(b))
		if !issp || (issp && b != prev) {
			buf = append(buf, b)
		}
		prev = b
	}
	return buf
}

// squeeze multiple duplicate characters in a row to a single character.
func squeeze(s []byte, unirange []*unicode.RangeTable) []byte {
	buf := make([]byte, 0, len(s))
	prev := s[0]
	buf = append(buf, prev)
	for i := 1; i < len(s); i++ {
		b := s[i]
		match := unicode.IsOneOf(unirange, rune(b))
		if !match || (match && b != prev) {
			buf = append(buf, b)
		}
		prev = b
	}
	return buf
}

// FirstHash computes the first iXhash digest.
// FirstHash mutates the provided msg []byte.
// FirstHash requires that the message contain at least 20 spaces/tabs
// and at least two newlines.
func FirstHash(msg []byte) string {
	if msg == nil {
		return ""
	}
	var (
		spaces   int
		newlines int
	)
	for _, c := range msg {
		switch c {
		case ' ', '\t':
			spaces++
		case '\n':
			newlines++
		}
	}
	if spaces < 20 || newlines < 2 {
		return ""
	}

	msg = bytes.Replace(msg, []byte{'\r', '\n'}, []byte{'\n'}, -1)

	buf := msg // reuse msg byte slice, squeezeSpaces returns a new one
	msg = squeezeSpaces(msg)

	buf = buf[:0]
	for _, b := range msg {
		if !unicode.IsOneOf(graphPCRE, rune(b)) {
			buf = append(buf, b)
		}
	}

	return md5hash(buf)
}

var (
	reSecondHashOK   = regexp.MustCompile(`((([<>\(\)\|@\*'!?,])|(:\/)).*?){3,}`)
	reRedundantStuff = regexp.MustCompile(`[[:cntrl:][:alnum:]%&#;=]+`)
)

// SecondHash computes the second iXhash digest.
// SecondHash mutates the provided msg []byte.
func SecondHash(msg []byte) string {
	if msg == nil {
		return ""
	}
	if match := reSecondHashOK.Find(msg); match == nil {
		return ""
	}

	msg = reRedundantStuff.ReplaceAll(msg, []byte{})
	msg = bytes.Replace(msg, []byte{'_'}, []byte{' '}, -1)

	msg = squeeze(msg, printPCRE)

	return md5hash(msg)
}

// ThirdHash computes the third iXhash digest.
// ThirdHash does not mutate the provided msg []byte.
// ThirdHash requires that the message contain at least eight consecutive
// non-space characters.
func ThirdHash(msg []byte) string {
	if msg == nil {
		return ""
	}
	var i int
	for _, b := range msg {
		if unicode.IsSpace(rune(b)) {
			i = 0
			continue
		}
		i++
		if i >= 8 {
			break
		}
	}
	if i < 8 {
		return ""
	}

	buf := make([]byte, 0, len(msg))
	for _, b := range msg {
		r := rune(b)
		if !(unicode.IsControl(r) || unicode.IsSpace(r) || r == '=') {
			buf = append(buf, b)
		}
	}
	buf = squeeze(buf, graphPCRE)
	return md5hash(buf)
}

// All computes all three hashes of the msg, which should be the body of an
// e-mail (no headers). All returns an array where the FirstHash result is in
// at index 0, the SecondHash is at index 1, and the ThirdHash is at index 2.
// If a hash could not be computed, it will be an empty string.
func All(msg []byte) [3]string {
	var ret [3]string
	b := make([]byte, len(msg))

	copy(b, msg)
	ret[0] = FirstHash(b)

	copy(b, msg)
	ret[1] = SecondHash(b)

	// ThirdHash does not mutate the slice.
	ret[2] = ThirdHash(msg)

	return ret
}

func Lookup(zone, digest string) (bool, error) {
	addrs, err := net.LookupHost(digest + "." + zone)
	if err != nil {
		return false, err
	}
	return len(addrs) > 0, nil
}
