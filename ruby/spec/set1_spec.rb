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

  describe "challenge 3" do

=begin
    Single-byte XOR cipher

    The hex encoded string:
    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    ... has been XOR'd against a single character. Find the key, decrypt the message.

    You can do this by hand. But don't: write code to do it for you.
    How? Devise some method for "scoring" a piece of English plaintext.
    Character frequency is a good metric. Evaluate each output and choose the one with the best score.
=end

    describe "solution" do
      it 'decrypts a message encrypted with single-byte XOR cypter' do
        m = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        expect(SingleByteXorCypher.maliciously_decrypt(m))
          .to eql "Cooking MC's like a pound of bacon"
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

      it 'counts occurrences of character bytes in a hex string' do
        expect(
          SingleByteXorCypher::Helpers.count_occurrences("616161626263")
        ).to eql([6, { 97 => 3, 98 => 2, 99 => 1 }])
      end

      it 'measures the frequencies of character bytes in a hex string' do
        expect(
          SingleByteXorCypher::Helpers.measure_frequencies("616161626263")
        ).to eql(97 => 0.5000, 98 => 0.3333, 99 => 0.1667)
      end

      it 'measures sum of the product of observed frequencies w/ known frequencies' do
        # this sets up a strategy for comparing frequency distributions
        # cf: Katz & Lindell's *Introduction To Modern Cryptography*, p. 12
        expect(
          SingleByteXorCypher::Helpers.sum_frequency_products("616161626263")
        ).to eql 0.0501
      end

      it "scores strings based on delta btw/ observed frequencies & ground truth" do
        expect(SingleByteXorCypher::Helpers.score("aaabbc")).to eql 0.0647
      end

      it "picks the string with the lowest score" do
        expect(
          SingleByteXorCypher::Helpers.pick_min_score(
            "thetoasteatingceremony",
            "jwwwwddhadkdklackaolbnd"
          )
        ).to eql "thetoasteatingceremony"
      end

      ##########################
      # PUT THE PIECES TOETHER #
      ##########################

      it "maliciously decrypts a hex string through brute force attack" do
        cyphertext = SingleByteXorCypher.encrypt("the toast eating ceremony", "C")
        expect(SingleByteXorCypher.maliciously_decrypt(cyphertext)).
          to eql "the toast eating ceremony"
      end
    end
  end
end
