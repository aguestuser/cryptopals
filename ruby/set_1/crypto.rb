require 'base64'

module Crypto
  class ::String
    def hex_to_base64 # => string
      [[self].pack('H*')].pack("m0")
    end

    def decode_hex # => Array<byte>
      [self].pack("H*").bytes
    end
  end

  class ::Array
    def encode_hex # => string
      self.map{ |b| b.to_s(16) }.join
    end
  end

  class << self
    # string, string ->  string
    def fixed_xor(hex1, hex2)
      hex1.decode_hex
        .zip(hex2.decode_hex)
        .map{ |a,b| a ^ b }
        .encode_hex
    end
  end
end
