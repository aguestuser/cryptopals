require 'base64'

module Crypto

  # TODO: get better frequencies
  # this is from: https://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
  LETTER_FREQUENCIES = {
    e: 12.02,
    t: 9.10,
    a: 8.12,
    o: 7.68,
    i: 7.31,
    n: 6.95,
    s: 6.28,
    r: 6.02,
    h: 5.92,
    d: 4.32,
    l: 3.98,
    u: 2.88,
    c: 2.71,
    m: 2.61,
    f: 2.30,
    y: 2.11,
    w: 2.09,
    g: 2.03,
    p: 1.82,
    b: 1.49,
    v: 1.11,
    k: 0.69,
    x: 0.17,
    q: 0.11,
    j: 0.10,
    z: 0.07,
  }

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

  class SingleByteXOR
    FREQUENCIES = {

    }
    class << self
      # string -> string
      def decrypt(hex)
        hex
      end
    end
  end
end
