require_relative "../app/crypto"

describe Crypto do
  describe "challenge solution" do
    it 'converts a hex string to a base64 string' do
      expect(("49276d206b696c6c696e6720796f757220627261696e206c696b6520612" +
             "0706f69736f6e6f7573206d757368726f6f6d").hex_to_base64).
        to eql "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    end
  end

  describe "challenge 2 solution" do
    it 'performs the fixed xor of two hex strings' do
      expect(Crypto.fixed_xor "1c0111001f010100061a024b53535009181c",
                              "686974207468652062756c6c277320657965").
        to eql "746865206b696420646f6e277420706c6179"
    end
  end

  describe "challenge 3 solution" do
=begin
Single-byte XOR cipher

The hex encoded string:
1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.
How? Devise some method for "scoring" a piece of English plaintext.
Character frequency is a good metric. Evaluate each output and choose the one with the best score.
=end

    # ASSUMPTIONS:
    # 1. our frequency count is accurate
    # 2. our

    it 'counts the frequencies of characters in a string'

    it 'scores a string based on how close the frequencies are to observed'

    it 'compares the scores of all possible keys in the ASCII character space'

    it 'decrypts a message encrypted with single-byte XOR cypter' do
      skip
      m = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
      expect(Crypto::SingleByteXOR.deccrypt(m)).to eql "???"
    end
  end
end
