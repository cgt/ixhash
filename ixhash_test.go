package ixhash

import "testing"

var sample = []byte(`From: "iXhash plugin test mail" <spamtrap@ixhash.net>
Message-ID: <mEsSaGeId@sOmEwHeRe.CoM>
To: admin@testsite.com
Subject: iXhash plugin test mail

This is an e-mail designed to test the iXhash plugin's functionality.
If you run this mail through SpamAssassin (using 'spamassassin -D IXHASH < iXhash.eml', you should see the plugin score with the list 'generic.ixhash.net'.
This is because the hashes this mail generates ( cbdc00eaaf002aad4448b75f47a9784f and 464d43b6999bdbdf6071b8b1d3f9a525 ) are permanently listed on that list.
Apart from that this mail is of no use.
This e-mail won't actually have the hashes described above because I
changed it.
`)

func TestSqueezeSpaces(t *testing.T) {
	expected := "all good	 things\n \n"
	x := []byte("all   good		 things\n \n\n")
	z := squeezeSpaces(x)
	if string(z) != expected {
		t.Fatalf("expected %q\n\t\tgot %q", expected, z)
	}
}

func TestFirstHash(t *testing.T) {
	expHash := "ca105c58bc49b645fecd9a5be7121a7a"
	body := sample

	hash := FirstHash(body)
	if hash == "" {
		t.Fatal("n/a")
	}

	if hash != expHash {
		t.Fatalf("actual hash %s does not match expected %s", hash, expHash)
	}
}

func TestSecondHash(t *testing.T) {
	expHash := "5eb74156843818e24d5b0b97c94a04c0"
	body := sample

	hash := SecondHash(body)
	if hash == "" {
		t.Fatal("n/a")
	}

	if hash != expHash {
		t.Fatalf("actual hash %s does not match expected %s", hash, expHash)
	}
}

func TestThirdHash(t *testing.T) {
	expHash := "32140a5a4405c0d0d89070740699ba21"
	body := sample

	hash := ThirdHash(body)
	if hash == "" {
		t.Fatal("n/a")
	}

	if hash != expHash {
		t.Fatalf("actual hash %s does not match expected %s", hash, expHash)
	}
}

func BenchmarkFirstHash(b *testing.B) {
	bx := make([]byte, len(sample))
	for i := 0; i < b.N; i++ {
		copy(bx, sample)

		hash := FirstHash(bx)
		if hash == "" {
			panic(1)
		}
	}
}

func BenchmarkSecondHash(b *testing.B) {
	bx := make([]byte, len(sample))
	for i := 0; i < b.N; i++ {
		copy(bx, sample)

		hash := SecondHash(bx)
		if hash == "" {
			panic(1)
		}
	}
}

func BenchmarkThirdHash(b *testing.B) {
	bx := make([]byte, len(sample))
	for i := 0; i < b.N; i++ {
		copy(bx, sample)

		hash := ThirdHash(bx)
		if hash == "" {
			panic(1)
		}
	}
}
