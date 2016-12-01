package ixhash

import "testing"

var sample = []byte(`This is an e-mail designed to test the iXhash plugin's functionality.
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
	expHash := "84a78da2a7d027c0391e514247c030de"
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
	expHash := "f9f247d546e84bc4df4f109cd56e28b3"
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
	expHash := "218f3c212aa5dda48abc1a604e431383"
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
