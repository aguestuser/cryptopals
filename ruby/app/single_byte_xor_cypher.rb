require "active_support"
require_relative "./crypto"
require_relative "./stats"

class SingleByteXorCypher
  include Crypto
  PERMITED_KEYS = Stats::ASCII_CHARS

  class << self
    # ascii_string, ascii char -> hex string
    def encrypt(plaintext, key)
      check_valid key
      bytes = plaintext.bytes
      Crypto.xor_bytes(
        bytes,
        Array.new(bytes.count) { key.bytes.first }
      ).encode_hex
    end

    # hex string, string -> ascii string
    def decrypt(cyphertext, key)
      check_valid key
      bytes = cyphertext.decode_hex
      Crypto.xor_bytes(
        bytes,
        Array.new(bytes.count) { key.bytes.first },
      ).encode_chars
    end

    # hex string -> [string, string]
    def decrypt_brute_force(cyphertext)
      hd_key, *tl_keys = *PERMITED_KEYS
      tl_keys.reduce(decrypt(cyphertext, hd_key)) do |best_guess, key|
        candidate_guess = decrypt(cyphertext, key)
        Helpers.pick_min_score(best_guess, candidate_guess)
      end
    end

    # # array<hex string> -> string|nil
    # def decrypt_first_encrypted(maybe_cyphertexts)
    #   if cyphertext = maybe_cyphertexts.find{ |str| is_encrypted?(str) }
    #     decrypt_brute_force(cyphertext)
    #   end
    # end

    # def is_encrypted?(maybe_cyphertext)
    #   score_keys(maybe_cyphertext)
    #     .find{ |k| k <= Stats::SUMMED_SQUARED_FREQUENCIES } ? true : false
    # end

    # # hex string -> array<float>
    # def score_keys(cyphertext)
    #   PERMITED_KEYS
    #     .map { |key| Helpers.score(fmt(decrypt(cyphertext, key))) }
    #     .map{ |score| Stats.round(score) }
    # end

    private

    # void | throw
    def check_valid(key)
      raise "Key must be a letter character" unless PERMITED_KEYS.include? key
    end
  end

  class Helpers
    class << self
      # string, string -> string
      def pick_min_score(str1, str2)
        return str1 if disqualified?(str2)
        return str2 if disqualified?(str1)
        score(str1) < score(str2) ? str1 : str2
      end

      # string -> float
      def score(str, strategy = :sum_frequency_deltas)
        send(strategy, str)
      end

      def disqualified?(str)
        !str.bytes.to_set.subset?(Stats::ASCII_BYTES)
      end

      # def delta_of_summed_frequency_products(hex)
      #   # measure the fit of a hex string's character distribution frequencey
      #   # w/ ground truth frequency distribution by comparing:
      #   # 1. the sum of the squares of the ground truth frequency of each char
      #   # --- with ---
      #   # 2. the sum of the product of the ground truth frequency
      #   #    of each char and the frequency of each char in the hext string
      #   # cf: Katz & Lindell's *Introduction To Modern Cryptography*, p. 12
      #   (Stats::SUMMED_SQUARED_FREQUENCIES - sum_frequency_products(hex)).abs
      # end

      # # hex_string -> double
      # def sum_frequency_products(hex)
      #   # sum the product of the observed frequency of every character
      #   # with the ground-truth frequency of every character
      #   obs_freqs = measure_frequencies(hex)
      #   Stats::FREQUENCIES_BY_BYTE.reduce(0.0) do |acc, (byte, freq)|
      #     Stats.round((acc + (freq * obs_freqs.fetch(byte, 0.0))))
      #   end
      # end

      # hex_string -> double
      def sum_frequency_deltas(str)
        Stats.round(measure_frequency_deltas(str).values.sum)
      end

      # ascii_string -> hash<byte, double>
      def measure_frequency_deltas(str)
        measure_frequencies(str).reduce({}) do |acc, (byte, observed_freq)|
          acc.tap do |a|
            a.merge!(byte => measure_frequency_delta(byte, observed_freq))
          end
        end
      end

      # double, byte -> double
      def measure_frequency_delta(byte, observed_freq)
        # if we have observed a frequency for a non-character byte
        # we will not find it in our frequency lookup table
        # since we wish these bytes to have no impact on our score
        # we return the observed_frequencey from our lookup attempt
        # so that the delta for non-character bytes will always be 0
        Stats.round(
          (
            observed_freq -
            Stats::FREQUENCIES_BY_BYTE.fetch(byte, observed_freq)
          ).abs
        )
      end

      # ascii_string -> hash<byte, double>
      def measure_frequencies(str)
        total, counts_by_byte = count_occurrences(str)
        counts_by_byte.transform_values do |count|
          Stats.round (count.to_f / total)
        end
      end

      # ascii_string -> [integer, hash<byte, integer>]
      def count_occurrences(str)
        map = str.bytes.reduce({}) do |acc, byte|
          acc.tap do |a|
            if Stats::FREQUENCIES_BY_BYTE.fetch(byte, false)
              # only include ascii character bytes in our count
              a.merge!(byte => acc.fetch(byte, 0) + 1) # increment count by 1
            end
          end
        end
        [map.values.sum, map]
      end
    end
  end
end
