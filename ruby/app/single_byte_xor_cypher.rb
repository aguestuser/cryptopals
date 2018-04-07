require "active_support"
require_relative "./crypto"
require_relative "./stats"

class SingleByteXorCypher
  include Crypto

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
      hd_key, *tl_keys = *Stats::ASCII_CHARS
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
      raise "Key must be an ASCII character" unless Stats::ASCII_CHARS.include? key
    end

    # string -> string
    def fmt(str)
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
        return Float::MAX if disqualified?(str)
        return (Stats::SUMMED_SQUARED_FREQUENCIES - sum_frequency_products(str)).abs
      end

      def disqualified?(str)
        !str.chars.to_set.subset?(Stats::ASCII_CHARS.to_set) ||
          !str.match(/[aeiou]/)
      end

      # hex_string -> double
      def sum_frequency_products(hex)
        # sum the product of the observed frequency of every character
        # with the ground-truth frequency of every character
        obs_freqs = measure_frequencies(hex)
        Stats::FREQUENCIES_BY_BYTE.reduce(0.0) do |acc, (byte, freq)|
          (acc + (freq * obs_freqs.fetch(byte, 0.0))).round(Stats::DECIMAL_PLACES)
        end
      end

      # hex_string -> hash<byte, double>
      def measure_frequencies(hex)
        total, counts_by_byte = count_occurrences(hex)
        counts_by_byte.transform_values do |count|
          (count.to_f / total).round(Stats::DECIMAL_PLACES)
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
