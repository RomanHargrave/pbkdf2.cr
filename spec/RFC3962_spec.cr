require "spec"
require "../src/PBKDF2"

describe PBKDF2, "when deriving keys" do
   it "should match the first test case in Appendix B of RFC 3962" do
      pbkdf_128 = PBKDF2.new("password", "ATHENA.MIT.EDUraeburn", 1_u64, OpenSSL::Digest.new("sha1"), (128 / 8).to_u64)
      pbkdf_256 = PBKDF2.new("password", "ATHENA.MIT.EDUraeburn", 1_u64, OpenSSL::Digest.new("sha1"), (256 / 8).to_u64)

      expect_128 = "cdedb5281bb2f801565a1122b2563515"
      expect_256 = "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837"

      key_128 = pbkdf_128.key
      key_256 = pbkdf_256.key

      if key_128
         key_128.hexstring.should eq expect_128
      else
         raise "128-Bit Test Key is Nil"
      end

      if key_256
         key_256.hexstring.should eq expect_256
      else
         raise "256-Bit Test Key is Nil"
      end
   end

   it "should match the second test case in Appendix B of RFC 3962" do
      pbkdf_128 = PBKDF2.new("password", "ATHENA.MIT.EDUraeburn", 2_u64, OpenSSL::Digest.new("sha1"), (128 / 8).to_u64)
      pbkdf_256 = PBKDF2.new("password", "ATHENA.MIT.EDUraeburn", 2_u64, OpenSSL::Digest.new("sha1"), (256 / 8).to_u64)

      expect_128 = "01dbee7f4a9e243e988b62c73cda935d"
      expect_256 = "01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86"

      key_128 = pbkdf_128.key
      key_256 = pbkdf_256.key

      if key_128
         key_128.hexstring.should eq expect_128
      else
         raise "128-Bit Test Key is Nil"
      end

      if key_256
         key_256.hexstring.should eq expect_256
      else
         raise "256-Bit Test Key is Nil"
      end
   end

   it "should match the third test case in Appendix B of RFC 3962" do
      pbkdf_128 = PBKDF2.new("password", "ATHENA.MIT.EDUraeburn", 1200_u64, OpenSSL::Digest.new("sha1"), (128 / 8).to_u64)
      pbkdf_256 = PBKDF2.new("password", "ATHENA.MIT.EDUraeburn", 1200_u64, OpenSSL::Digest.new("sha1"), (256 / 8).to_u64)

      expect_128 = "5c08eb61fdf71e4e4ec3cf6ba1f5512b"
      expect_256 = "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13"

      key_128 = pbkdf_128.key
      key_256 = pbkdf_256.key

      if key_128
         key_128.hexstring.should eq expect_128
      else
         raise "128-Bit Test Key is Nil"
      end

      if key_256
         key_256.hexstring.should eq expect_256
      else
         raise "256-Bit Test Key is Nil"
      end
   end

   it "should match the fourth test case in Appendix B of RFC 3962" do
      pbkdf_128 = PBKDF2.new("password", Bytes[18, 52, 86, 120, 120, 86, 52, 18], 5_u64, OpenSSL::Digest.new("sha1"), (128 / 8).to_u64)
      pbkdf_256 = PBKDF2.new("password", Bytes[18, 52, 86, 120, 120, 86, 52, 18], 5_u64, OpenSSL::Digest.new("sha1"), (256 / 8).to_u64)

      expect_128 = "d1daa78615f287e6a1c8b120d7062a49"
      expect_256 = "d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee"

      key_128 = pbkdf_128.key
      key_256 = pbkdf_256.key

      if key_128
         key_128.hexstring.should eq expect_128
      else
         raise "128-Bit Test Key is Nil"
      end

      if key_256
         key_256.hexstring.should eq expect_256
      else
         raise "256-Bit Test Key is Nil"
      end
   end

   it "should match the fifth test case in Appendix B of RFC 3962" do
      pbkdf_128 = PBKDF2.new("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase equals block size", 1200_u64, OpenSSL::Digest.new("sha1"), (128 / 8).to_u64)
      pbkdf_256 = PBKDF2.new("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase equals block size", 1200_u64, OpenSSL::Digest.new("sha1"), (256 / 8).to_u64)

      expect_128 = "139c30c0966bc32ba55fdbf212530ac9"
      expect_256 = "139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1"

      key_128 = pbkdf_128.key
      key_256 = pbkdf_256.key

      if key_128
         key_128.hexstring.should eq expect_128
      else
         raise "128-Bit Test Key is Nil"
      end

      if key_256
         key_256.hexstring.should eq expect_256
      else
         raise "256-Bit Test Key is Nil"
      end
   end

   it "should match the sixth test case in Appendix B of RFC 3962" do
      pbkdf_128 = PBKDF2.new("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase exceeds block size", 1200_u64, OpenSSL::Digest.new("sha1"), (128 / 8).to_u64)
      pbkdf_256 = PBKDF2.new("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase exceeds block size", 1200_u64, OpenSSL::Digest.new("sha1"), (256 / 8).to_u64)

      expect_128 = "9ccad6d468770cd51b10e6a68721be61"
      expect_256 = "9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a"

      key_128 = pbkdf_128.key
      key_256 = pbkdf_256.key

      if key_128
         key_128.hexstring.should eq expect_128
      else
         raise "128-Bit Test Key is Nil"
      end

      if key_256
         key_256.hexstring.should eq expect_256
      else
         raise "256-Bit Test Key is Nil"
      end
   end

   it "should match the seventh test case in Appendix B of RFC 3962" do
      pbkdf_128 = PBKDF2.new(Bytes[240, 157, 132, 158], "EXAMPLE.COMpianist", 50_u64, OpenSSL::Digest.new("sha1"), (128 / 8).to_u64)
      pbkdf_256 = PBKDF2.new(Bytes[240, 157, 132, 158], "EXAMPLE.COMpianist", 50_u64, OpenSSL::Digest.new("sha1"), (256 / 8).to_u64)

      expect_128 = "6b9cf26d45455a43a5b8bb276a403b39"
      expect_256 = "6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52"

      key_128 = pbkdf_128.key
      key_256 = pbkdf_256.key

      if key_128
         key_128.hexstring.should eq expect_128
      else
         raise "128-Bit Test Key is Nil"
      end

      if key_256
         key_256.hexstring.should eq expect_256
      else
         raise "256-Bit Test Key is Nil"
      end
   end
end
