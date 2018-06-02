require_relative "../app/crypto"
require_relative "../app/single_byte_xor_cypher"

describe Crypto do
  describe "challenge 1: Convert hex to base64" do
=begin
 The string:
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

Should produce:
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
=end

    describe "solution" do
      it 'converts a hex string to a base64 string' do
        expect(("49276d206b696c6c696e6720796f7572" +
                "20627261696e206c696b65206120706f" +
                "69736f6e6f7573206d757368726f6f6d").hex_to_base64)
          .to eql "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
      end
    end

    describe "helpers" do
      it "decodes a hex string to bytes" do
        expect("49276d".decode_hex).to eql [73, 39, 109]
        expect("49276d".decode_hex).to eql [0b01001001, 0b00100111, 0b01101101]
      end

      it "encodes bytes as a plaintext character string" do
        expect([73, 39, 109].encode_chars).to eql "I'm"
        expect([0b01001001, 0b00100111, 0b01101101].encode_chars).to eql "I'm"
      end

      it "encodes a a byte array as a hex string" do
        expect([73, 39, 109].encode_hex).to eql "49276d"
        expect([0b01001001, 0b00100111, 0b01101101].encode_hex).to eql "49276d"
      end
    end
  end

  describe "challenge 2: Fixed XOR" do
=begin

    Write a function that takes two equal-length buffers and produces their XOR combination.

    If your function works properly, then when you feed it the string:

    1c0111001f010100061a024b53535009181c

    ... after hex decoding, and when XOR'd against:

    686974207468652062756c6c277320657965

    ... should produce:

    746865206b696420646f6e277420706c6179
=end
    let(:hex1){ "1c0111001f010100061a024b53535009181c" }
    let(:hex2){ "686974207468652062756c6c277320657965" }

    describe "solution" do
      it 'performs the fixed xor of two hex strings' do
        expect(Crypto.xor_hex(hex1, hex2)).
          to eql "746865206b696420646f6e277420706c6179"
      end
    end

    describe "helpers" do
      it "performs the fixed xor of two byte arrays" do
        expect(Crypto.xor_bytes([0b10101010], [0b01010101])).
          to eql [0b11111111]
      end
    end
  end

  describe "challenge 3: Single-byte XOR Cypher" do

=begin
    Single-byte XOR cipher

    The hex encoded string:
    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    ... has been XOR'd against a single character. Find the key, decrypt the message.

    You can do this by hand. But don't: write code to do it for you.
    How? Devise some method for "scoring" a piece of English plaintext.
    Character frequency is a good metric. Evaluate each output and choose the one with the best score.
=end

    describe "solutions" do
      let(:strategy){}
      let(:flag){ "Cooking MC's like a pound of bacon" }
      let(:decrypted_msg) do
        SingleByteXorCypher.decrypt_brute_force(
          '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736',
          strategy
        )
      end

      describe "using summed frequency delta strategy" do
        let(:strategy){ :sum_frequency_deltas }
        it "decrypts the message" do
          expect(decrypted_msg).to eql flag
        end
      end

      describe "using delta of summed frequency products strategy" do
        let(:strategy){ :delta_of_summed_frequency_products }
        it "decrypts the message" do
          expect(decrypted_msg).to eql flag
        end
      end
    end

    describe "module" do

      ##################
      # PUBLIC METHODS #
      ##################

      # let's make sure we can encrypt and decrypt stuff correctly...

      it "encrypts a string by XOR-ing its byte repr. w/ a repeated char byte" do
        expect(SingleByteXorCypher.encrypt("hello world", "c")).
          to eql "0b060f0f0c43140c110f07"
      end

      it "decrypts a hex string given the key the plaintext was XOR'ed with" do
        expect(SingleByteXorCypher.decrypt("0b060f0f0c43140c110f07", "c")).
          to eql "hello world"
      end

      ##################
      # HELPER METHODS #
      ##################

      # now let's build up to our solution bit-by-bit..
      it 'counts occurrences of ASCII bytes in a string' do
        expect(
          SingleByteXorCypher::Helpers.count_occurrences("cccbba")
        ).to eql([6, { 97 => 1, # a
                       98 => 2, # b
                       99 => 3 }]) #c
      end

      it "counts non-character bytes" do
        expect(
          SingleByteXorCypher::Helpers.count_occurrences("ccc bb! a?")
        ).to eql([
                   10,
                   {
                     32 => 2, # SPC
                     33 => 1, # ?
                     63 => 1, # !
                     97 => 1, # a
                     98 => 2, # b
                     99 => 3, # c
                   }])
      end

      it 'measures the frequencies of ASCII bytes in a string' do
        expect(
          SingleByteXorCypher::Helpers.measure_frequencies("cccbba")
        ).to eql(97 => 0.166667,
                 98 => 0.333333,
                 99 => 0.500000)
      end

      it "measures frequency of non-character, non-whitespace bytes" do
        expect(
          SingleByteXorCypher::Helpers.measure_frequencies("ccc bb! a?")
        ).to eql(32 => 0.2,
                 33 => 0.1,
                 63 => 0.1,
                 97 => 0.1,
                 98 => 0.2,
                 99 => 0.3)
      end

      describe "scoring" do
        describe "summed frequency delta strategy" do
          it "measures the deltas between observed frequencies and ground truth" do
            expect(
              SingleByteXorCypher::Helpers.measure_frequency_deltas("cccbba")
            ).to eql(97 => 0.0913904,
                     98 => 0.310418,
                     99 => 0.474272)
          end

          it "measures deltas for non-character non-whitespace bytes" do
            expect(
              SingleByteXorCypher::Helpers.measure_frequency_deltas("ccc bb! a?")
            ).to eql(32 => 0.033334,
                     33 => 0.0996931,
                     63 => 0.0999793,
                     97 => 0.0247234,
                     98 => 0.177086,
                     99 => 0.274272)
          end

          it "sums the deltas for all observed frequencies" do
            expect(
              SingleByteXorCypher::Helpers.sum_frequency_deltas("cccbba")
            ).to eql 0.876080
          end

          it "sums the deltas for observed non-char frequencies" do
            expect(
              SingleByteXorCypher::Helpers.sum_frequency_deltas("aaa bb? c!")
            ).to eql 0.709088
          end

          it "scores strings w.r.t. their summed frequency deltas" do
            expect(
              SingleByteXorCypher::Helpers.score("cccbba", :sum_frequency_deltas)
            ).to eql 0.876080
          end

          it "considers whitespace when scoring strings" do
            expect(
              SingleByteXorCypher::Helpers.score("thetoasteatingceremony")
            ).not_to(
              eql(
                SingleByteXorCypher::Helpers.score("the toast eatingceremony")
              )
            )
          end

          it "picks the string with the smallest score" do
            expect(
              SingleByteXorCypher::Helpers.pick_min_score(
                "cccbba",
                "the toast eating ceremony"
              )
            ).to eql "the toast eating ceremony"
          end
        end

        describe "summed frequency product strategy" do
          # see: Katz & Lindell's *Introduction To Modern Cryptography*, p. 12

          it 'measures sum of the product of observed frequencies w/ known frequencies' do
            # this sets up a strategy for comparing frequency distributions
            expect(
              SingleByteXorCypher::Helpers.sum_frequency_products("cccbba")
            ).to eql 0.0330481
          end

          it "scores strings based on delta btw/ observed frequencies & ground truth" do
            expect(
              SingleByteXorCypher::Helpers.score("cccbba", :delta_of_summed_frequency_products)
            ).to eql 0.0357351
          end

          it "picks the string with the lowest score" do
            expect(
              SingleByteXorCypher::Helpers.pick_min_score(
                "the toast eating ceremony",
                "jwwwwddhadkdklackaolbnd"
              )
            ).to eql "the toast eating ceremony"
          end
        end
      end

      ##########################
      # PUT THE PIECES TOETHER #
      ##########################

      it "brute force decrypts a hex string with summed frequency strategy" do
        key = SingleByteXorCypher::PERMITED_KEYS.to_a.sample
        expect(
          SingleByteXorCypher.decrypt_brute_force(
            SingleByteXorCypher.encrypt("the toast eating ceremony", key)
          )
        ).to eql "the toast eating ceremony"
      end

      it "brute-force decrypts with delta of summed frequency products strategy" do
        key = SingleByteXorCypher::PERMITED_KEYS.to_a.sample
        expect(
          SingleByteXorCypher.decrypt_brute_force(
            SingleByteXorCypher.encrypt("the toast eating ceremony", key),
            :delta_of_summed_frequency_products
          )
        ).to eql "the toast eating ceremony"
      end
    end
  end

  xdescribe "challenge 4: Detect single-character XOR" do
=begin
  Detect single-character XOR

  One of the 60-character strings in this file has been encrypted by single-character XOR.

  Find it.

  (Your code from #3 should help.)
=end

    describe "solution" do
      it "detects which hex string has been encrypted by single-character XOR" do
        strings = File.readlines("spec/fixtures/challenge_4_hex_strings.txt")
        expect(SingleByteXorCypher.decrypt_first_encrypted(strings))
          .to eql "hmmm"
      end
    end

    describe "methods" do
      describe "given an array of non-encrypted strings" do
        it "returns nil" do
          expect(
            SingleByteXorCypher.decrypt_first_encrypted(
              [
                "dkdkdkkdka;adkdkdkw09c9a",
                "poienenneas;oewlkadsh;ij",
                "o4a;939x9v9a';fdkvksa;lk"
              ]
            )
          ).to be nil
        end
      end

      describe "given an arry containing two encrypted strings" do
        it "returns plaintext for the first encrypted string" do
          expect(
            SingleByteXorCypher.decrypt_first_encrypted(
              [
                "dkdkdkkdka;adkdkdkw09c9a",
                SingleByteXorCypher.encrypt("the toast eating ceremony", "x"),
                "o4a;939x9v9a';fdkvksa;lk",
                SingleByteXorCypher.encrypt("the tea drinking ceremony", "C"),
              ]
            )
          ).to eql "the toast eating ceremony"
        end
      end

      it "detects that a string not has been xor encrypted" do
        expect(SingleByteXorCypher.is_encrypted?("dkdka;dkdkaowowowkdkdkdk"))
          .to be false
      end

      it"detects that a string has been xor encrypted" do
        expect(SingleByteXorCypher.is_encrypted?(
          SingleByteXorCypher.encrypt("hello world", "c")
        )).to be true
      end

      it "enumerates the scores for all non-disqualified candidate keys" do
        expect(SingleByteXorCypher.score_keys("0b060f0f0c43140c110f07"))
          .to eql [0.0462, 0.0647, 0.0647]
      end
    end
  end
end
