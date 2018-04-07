require 'base64'

module Crypto
  class << self
    # string, string ->  string
    def xor_hex(hex1, hex2)
      xor_bytes(
        hex1.decode_hex,
        hex2.decode_hex
      ).encode_hex
    end

    # byte-array, byte-array -> byte-array
    def xor_bytes(as, bs)
      as.zip(bs).map{ |a,b| a ^ b }
    end
  end

  # TODO: extract these to a monkey_patches file?
  class ::String
    # hex string -> base64-encoded string
    def hex_to_base64
      [[self].pack('H*')].pack("m0")
    end

    # hex string -> array<byte>
    def decode_hex
      [self].pack("H*").bytes
    end

    # string -> hex string
    def encode_hex
      self.unpack("H*").first
    end
  end

  class ::Array
    # array<byte> -> hex string
    def encode_hex
      encode_chars.encode_hex
    end

    # array<byte> -> plaintext string
    def encode_chars
      self.map{ |b| b.chr }.join
    end
  end
end
