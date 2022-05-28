package pem

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"reflect"
	"testing"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		name          string
		fixture       string
		wantHex       string
		wantGenerator string
	}{
		{
			name:          "dh params 32 bit",
			fixture:       "dhparam4.pem",
			wantHex:       "8c25bd6b",
			wantGenerator: "02",
		},
		{
			name:          "dh params 32 bit #2",
			fixture:       "dhparam5.pem",
			wantHex:       "bc3da163",
			wantGenerator: "02",
		},
		{
			name:          "dh params 128 bit",
			fixture:       "dhparam3.pem",
			wantHex:       "00d98e4ab3023110f97f069eda6b0bbcfb",
			wantGenerator: "02",
		},
		{
			name:          "dh parmas 512 bit",
			fixture:       "dhparam2.pem",
			wantHex:       "00be2c109fc1f1c9e47d6277f70886b7ea8ca747dd2731b47b9f57547bfd064117eb804702036d00dab154a935f7be0367235b2c0e45b59563b10ad44e95773403",
			wantGenerator: "02",
		},
		{
			name:          "dh parmas 2048 bit",
			fixture:       "dhparam0.pem",
			wantHex:       "00c55aa4ef35c8f9c2cf640edcab88b1511e2a83276af663c3732f3d5cefd3de2e3078fbde639da643cdd2e7016a402b2291da8f0d9d3835bb7f011c60491d63ed7ee21c0c9bf2802e0ee26ff9429f75d5d309203311c65a7b5b99a2a707ee997dd8b011799f2ec260eb8e5e89a5a4944409395ee25babaa489706c21fbd064658afa95489d4ada2f2bd94da2cd96afca85f245716350bb91e20be92c67971526144da3c1c1c0e76995c55191a7be9a96e7f8b9add251dfc80fbc5fbaced50bad628a67b844df3e456582c4dc7cf58be027bd85b56a6f19fd512c3e8c517f587e4a0b6921584fa81b9376cc06063ea5ffb704fc45843adb042b4acd5894eb434ab",
			wantGenerator: "02",
		},
		{
			name:          "dh parmas 4096 bit",
			fixture:       "dhparam-4096.pem",
			wantHex:       "00eb588a172722e020661f6fa7a839deb2b923734b9f12ae12e7bd9ca1347de61bf2b2cac0f35f07a04301200722995b8b7be39db3316ec122746ba891b075fecf90100949e23ae1a0df97150aa7256fd17a6d3c61599ced59080b2810c8082d51be57882c7729e6ab7fff6944b916a16c2f2a10a6462cd607b53feaf32a8da7d15e8e606cd8b1f0e87823ba3907fe5e5b9a71408f1b279a6e055d4a025c137965ac0cbe013e166d12cb95c5b990a371e45b269cdc41d90af44e668be5c29dbd801db8681e61957cf5882bfd2644dd2e4c80dd4f49d506cf31a536e1a7da7d03f123a196ec014459d5557e30e41140ece2528140d504b1755e525de6d23e1e77a49874b3fb8fde301619ca436c971e095e6cd4a138d4d1ce065135ac128af72ad7ccd479be21ac76706f576dcbec915facee1cb3727b3550bcd61a0ca76bd121aba046d929c3aa7af44518ea0137768d986e9bb8813c55587a6a34a8fa05a582cd54ed3a26d3878c19ff8ece0243ad9de4b0564ad09517ed497a4be726cbdd9b2d379a1e52b0e36d9ab06789048cfff45ca44a74ec65079ee75fdfe6d08a429da57719e4773b11038f07a61b342ebbabe4e262c59c26e34b358345e5d4711dae9e1d22dbf29e1e8cf64af1a869eb05f4f68e9a8c2b67b82c90ec05ae62e423484475b1397b5a18777d3461312d108deb49fd04bdaff21fdedaaadd8c30c837a173",
			wantGenerator: "02",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(fmt.Sprintf("fixtures/%s", tt.fixture))
			if err != nil {
				t.Fatal(err)
			}

			block, _ := pem.Decode(b)

			if block == nil || block.Type != "DH PARAMETERS" {
				t.Fatal("failed to decode PEM block containing public key")
			}

			got, err := Decode(b)
			if err != nil {
				t.Fatal(err)
			}

			prime, err := hex.DecodeString(tt.wantHex)
			if err != nil {
				t.Fatal(err)
			}

			wantPrime := new(big.Int)
			wantPrime.SetBytes(prime)

			gen, err := hex.DecodeString(tt.wantGenerator)
			if err != nil {
				t.Fatal(err)
			}

			wantGen := new(big.Int)
			wantGen.SetBytes(gen)

			want := &Params{
				Prime:     wantPrime,
				Generator: wantGen,
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("got\n%+v\nwant\n%+v", got, want)
			}
		})
	}
}
