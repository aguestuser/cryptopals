require 'base64'

module Crypto
  class << self
    def hex_to_base64(hex_str)
      [[hex_str].pack('H*')].pack("m0")
    end
  end
end
