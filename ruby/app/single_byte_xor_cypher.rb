require "active_support"
require_relative "./crypto"

class SingleByteXorCypher
  include Crypto

  SIG_DIGITS = 4
  SPACE_BYTE = 0b00100000

  ASCII_BYTES = (1..127).to_set.freeze
  ASCII_CHARS = ASCII_BYTES.map(&:chr)
  LETTER_CHARS = %w[A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
                    a b c d e f g h i j k l m n o p q r s t u v w x y z]

  # SOURCE: https://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
  FREQUENCIES_BY_CHAR = { a: 0.0812, b: 0.0149, c: 0.0271, e: 0.1202, d: 0.0432,
                          f: 0.0230, g: 0.0203, h: 0.0592, i: 0.0731, j: 0.0010,
                          k: 0.0069, l: 0.0398, m: 0.0261, n: 0.0695, o: 0.0768,
                          p: 0.0182, q: 0.0011, r: 0.0602, s: 0.0628, t: 0.0910,
                          u: 0.0288, v: 0.0111, w: 0.0209, x: 0.0017, y: 0.0211,
                          z: 0.0007 }.freeze
  FREQUENCIES_BY_BYTE = FREQUENCIES_BY_CHAR.transform_keys{ |k| k.to_s.ord }
  SUMMED_SQUARED_FREQUENCIES = 0.0647

  class << self
    # string, string -> hex string
    def encrypt(plaintext, key)
      check_valid key
      bytes = plaintext.bytes
      Crypto.xor_bytes(
        bytes,
        Array.new(bytes.count) { key.bytes.first }
      ).encode_hex
    end

    # hex string, string -> hex string
    def decrypt(cyphertext, key)
      check_valid key
      bytes = cyphertext.decode_hex
      Crypto.xor_bytes(
        bytes,
        Array.new(bytes.count) { key.bytes.first },
      ).encode_chars
    end

    # hex string -> [string, string]
    def maliciously_decrypt(cyphertext)
      hd_key, *tl_keys = *ASCII_CHARS
      tl_keys.reduce(decrypt(cyphertext, hd_key)) do |best_guess, key|
        candidate_guess = decrypt(cyphertext, key)
        a = fmt(best_guess)
        b = fmt(candidate_guess)
        Helpers.pick_min_score(a, b) == a ? best_guess : candidate_guess
      end
    end

    private

    # void | throw
    def check_valid(key)
      raise "Key must be an ASCII character" unless ASCII_CHARS.include? key
    end

    # string -> string
    def fmt(str)
      # TODO: if we included all ascii chars in our ground truth freqs,
      # this would be unnecessary
      str.downcase.gsub(/[\s\.,'\(\)!]/, "")
    end
  end

  class Helpers
    class << self
      # string, string -> string
      def pick_min_score(str1, str2)
        score(str1) < score(str2) ? str1 : str2
      end

      def score(str)
        # measure the fit of a hex string's character distribution frequencey
        # w/ ground truth frequency distribution by comparing:
        # 1. the sum of the squares of the ground truth frequency of each char
        # --- with ---
        # 2. the sum of the product of the ground truth frequency
        #    of each char and the frequency of each char in the hext string
        # cf: Katz & Lindell's *Introduction To Modern Cryptography*, p. 12
        # (as stop-gap heuristic, throw out non-letter characters, but
        #  it would be better to include all ASCII chars in our baseline)
        return Float::MAX unless all_letter_chars?(str)
        return (SUMMED_SQUARED_FREQUENCIES - sum_frequency_products(str)).abs
      end

      def all_letter_chars?(str)
        str.chars.to_set.subset?(LETTER_CHARS.to_set)
      end

      # hex_string -> double
      def sum_frequency_products(hex)
        # sum the product of the observed frequency of every character
        # with the ground-truth frequency of every character
        observed_freqs = measure_frequencies(hex)
        FREQUENCIES_BY_BYTE.reduce(0.0) do |acc, (byte, freq)|
          (acc + (freq * observed_freqs.fetch(byte, 0.0))).round(SIG_DIGITS)
        end
      end

      # hex_string -> hash<byte, double>
      def measure_frequencies(hex)
        total, counts_by_byte = count_occurrences(hex)
        counts_by_byte.transform_values do |count|
          (count.to_f / total).round(SIG_DIGITS)
        end
      end

      # hex_string -> [integer, hash<byte, integer>]
      def count_occurrences(hex)
        map = hex.decode_hex.reduce({}) do |acc, byte|
          acc.merge(byte => acc.fetch(byte, 0) + 1)
        end
        [map.values.sum, map]
      end
    end
  end
end
