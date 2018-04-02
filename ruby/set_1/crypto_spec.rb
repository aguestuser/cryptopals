require_relative "./crypto"

describe Crypto do
  # challenge 1
  it 'converts a hex string to a base64 string' do
    expect(Crypto.hex_to_base64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").
      to eql "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
  end
end
