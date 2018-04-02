require_relative "./crypto"

describe Crypto do
  # challenge 1
  it 'converts a hex string to a base64 string' do
    expect("49276d206b696c6c696e6720796f757220627261696e206c696b6520612" +
           "0706f69736f6e6f7573206d757368726f6f6d".hex_to_base64).
      to eql "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
  end

  # challenge 2
  it 'performs the fixed xor of two hex strings' do
    expect(Crypto.fixed_xor "1c0111001f010100061a024b53535009181c",
                            "686974207468652062756c6c277320657965").
      to eql "746865206b696420646f6e277420706c6179"
  end
end
