module Stats
  DECIMAL_PLACES = 4
  ASCII_CHARS = %w[A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
                   a b c d e f g h i j k l m n o p q r s t u v w x y z].to_set
   # SOURCE: https://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
  FREQUENCIES_BY_CHAR = { a: 0.0812, b: 0.0149, c: 0.0271, e: 0.1202, d: 0.0432,
                          f: 0.0230, g: 0.0203, h: 0.0592, i: 0.0731, j: 0.0010,
                          k: 0.0069, l: 0.0398, m: 0.0261, n: 0.0695, o: 0.0768,
                          p: 0.0182, q: 0.0011, r: 0.0602, s: 0.0628, t: 0.0910,
                          u: 0.0288, v: 0.0111, w: 0.0209, x: 0.0017, y: 0.0211,
                          z: 0.0007 }.freeze
  FREQUENCIES_BY_BYTE = FREQUENCIES_BY_CHAR.transform_keys{ |k| k.to_s.ord }
  SUMMED_SQUARED_FREQUENCIES = 0.0647
end
