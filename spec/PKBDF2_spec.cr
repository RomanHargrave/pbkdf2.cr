require "spec"
require "../src/PBKDF2"

describe Slice do
   describe "#^" do
      lhs = Slice[0xDE, 0xAD, 0xBE, 0xEF]
      rhs = Slice[0xCA, 0xFE, 0xBA, 0xBE]
      yld = Slice[0xDE ^ 0xCA,
                  0xAD ^ 0xFE,
                  0xBE ^ 0xBA,
                  0xEF ^ 0xBE]

      it "computes exclusive-or between two slices" do
         (lhs ^ rhs).should eq yld
      end
   end

   describe "#concat" do
      lhs      = Slice[0x01, 0x23, 0x45, 0x67, 0x89]
      rhs      = Slice[0xAB, 0xCD, 0xEF]
      product  = Slice[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]

      it "combines lhs and rhs slices, returning flatten [ lhs, rhs ]" do
         lhs.concat(rhs).should eq product
      end
   end
end

describe OpenSSL::Digest do
   describe "#hmac" do
      pass = "1234567890"
      data = "0987654321"

      algos = {"MD4" => :md4, "MD5" => :md5, "RIPEMD160" => :ripemd160,
               "SHA1" => :sha1, "SHA224" => :sha224, "SHA256" => :sha256,
               "SHA384" => :sha384, "SHA512" => :sha512}

      algos.each do |name, sym|
         it "supports #{name}" do
            digest = OpenSSL::Digest.new(name)
            digest.hmac(pass, data).should eq OpenSSL::HMAC.digest(sym, pass, data)
         end
      end
   end
end

describe PBKDF2 do
   password        = "the quick brown fox jumped over the lazy dog"
   salt            = "abcdefg"
   iterations      = 5000_u32
   supported_algos = {
      "MD4"       => Bytes[5, 250, 211, 175, 39, 93, 97, 64, 73, 140, 220, 47, 54, 39, 202, 49],
      "MD5"       => Bytes[78, 77, 156, 19, 7, 232, 223, 240, 189, 93, 250, 78, 119, 71, 231, 98],
      "RIPEMD160" => Bytes[231, 106, 97, 3, 91, 49, 181, 3, 143, 101, 224, 146, 32, 231, 42, 159, 48, 95, 26, 226],
      "SHA1"      => Bytes[73, 0, 124, 95, 3, 238, 76, 75, 42, 60, 245, 38, 107, 68, 15, 155, 166, 200, 75, 164],
      "SHA224"    => Bytes[73, 136, 231, 110, 96, 90, 16, 223, 83, 49, 9, 128, 25, 26, 37, 242, 67, 174, 205, 78, 18, 47, 69, 237, 82, 82, 12, 37],
      "SHA256"    => Bytes[79, 87, 75, 115, 164, 243, 125, 173, 115, 88, 249, 139, 19, 249, 45, 60, 159, 221, 235, 117, 106, 87, 171, 91, 113, 199, 175, 191, 224, 194, 249, 219],
      "SHA384"    => Bytes[182, 215, 137, 159, 181, 173, 61, 120, 55, 4, 207, 3, 180, 116, 18, 109, 47, 104, 0, 218, 211, 49, 9, 191, 106, 71, 97, 12, 150, 74, 58, 139, 113, 235, 87, 97, 201, 210, 236, 95, 217, 92, 160, 87, 207, 32, 193, 96],
      "SHA512"    => Bytes[111, 82, 116, 120, 68, 54, 246, 172, 68, 34, 96, 29, 13, 199, 139, 49, 97, 130, 85, 11, 194, 126, 131, 201, 250, 77, 18, 108, 120, 198, 60, 106, 99, 30, 154, 35, 73, 62, 11, 181, 86, 251, 14, 39, 87, 175, 211, 226, 117, 193, 45, 99, 14, 92, 38, 112, 180, 224, 239, 215, 124, 231, 103, 253]
   }

   supported_algos.each do |algo, output|
      it "supports #{algo}" do
         digest = OpenSSL::Digest.new(algo)
         pbkdf  = PBKDF2.new(password, salt, iterations, digest)
         pbkdf.key.should eq output
      end
   end

   it "should yield the requested key length" do
      digest = OpenSSL::Digest.new("sha1")
      [128, 256, 512, 1024, 2048, 4096].each do |len|
         pbkdf = PBKDF2.new(password, salt, 5, digest, len.to_u64)
         if key = pbkdf.key
            key.size.should eq len
         else
            raise "No key generated"
         end
      end
   end
end
