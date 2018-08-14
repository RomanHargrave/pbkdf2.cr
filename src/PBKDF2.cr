require "openssl"
require "openssl/hmac"

class OpenSSL::Digest
   def hmac(p_key, p_data)
      # Deriving a symbol at runtime is not possible, nor does there exist a path to an HMAC digest instance from OpenSSL::Digest
      # A symbol could be accepted by PKBDF2#initialize which would in turn create the digest object and remember the symbol for use instantiating HMAC
      # However, that would be less straightforward than a hack like this
      evp_sym = case self.name.upcase
                when "MD4"       then :md4
                when "MD5"       then :md5
                when "RIPEMD160" then :ripemd160
                when "SHA1"      then :sha1
                when "SHA224"    then :sha224
                when "SHA256"    then :sha256
                when "SHA384"    then :sha384
                when "SHA512"    then :sha512
                else raise "#hmac was called on an OpenSSL::Digest object, the algorithm of which (#{self.name.upcase}) lacks a corresponding HMAC implementation"
                end

      OpenSSL::HMAC.digest(evp_sym, p_key, p_data)
   end
end

# Slice additions
struct Slice(T)

   # XOR
   def ^(rhs : self)
      raise ArgumentError.new(message = "LHS and RHS Slices must have same size") unless self.size == rhs.size

      lhs = self.clone
      rhs.each_with_index do |rhb, idx|
         lhs[idx] = lhs[idx] ^ rhb
      end
      lhs
   end

   # Concat
   def concat(rhs : self)
      product = Slice(T).new(self.size + rhs.size)
      rhs_dest = product[self.size, rhs.size]
      self.copy_to(product)
      rhs.copy_to(rhs_dest)
      product
   end
end

class PBKDF2

   alias UInt = UInt8 | UInt16 | UInt32 | UInt64

   @key              : Bytes | Nil
   @password         : Bytes
   @salt             : Bytes
   @iterations       : UInt
   @hash_function    : OpenSSL::Digest
   @max_key_length   : UInt64
   @key_length       : UInt64

   def initialize(p_password, p_salt,
                  @iterations : UInt,
                  @hash_function : OpenSSL::Digest = OpenSSL::Digest.new("sha256"),
                  @key_length : UInt64 = 0)

      @password       = p_password.to_slice
      @salt           = p_salt.to_slice
      @max_key_length = ((2_u64 ** 32_u64 - 1_u64) * @hash_function.digest_size)
      @key_length     = @hash_function.digest_size.to_u64 if @key_length < 1
      @key            = nil

      raise ArgumentError.new(message = "Iteration count must be at least 1") if @iterations < 1
      raise ArgumentError.new(message = "Key length exceeds maximum length of #{@max_key_length} bytes") if @key_length > @max_key_length
   end

   def key
      compute! if @key.nil?
      if @key
         @key
      else
         raise "Failed to compute key"
      end
   end

   # Setters for salt/password
   def password=(p_password)
      @key = nil
      @password = p_password.to_slice
   end

   def salt=(p_salt)
      @key = nil
      @salt = p_salt.to_slice
   end

   ###########################################################################################
   # PKBDF 2 Implementation                                                                  #
   ###########################################################################################

   private def prf(p_data)
      @hash_function.hmac(@password, p_data)
   end

   private def compute_block(p_block_num : UInt32)
      # Create slice with BE 32-bit block num and concat with salt
      block_salt = Bytes.new(4)
      IO::ByteFormat::BigEndian.encode(p_block_num, block_salt)

      u : Bytes = prf(@salt.concat(block_salt))

      accum : Bytes = u

      2.upto(@iterations) do
         u     = prf(u)
         accum = accum ^ u
      end

      accum
   end

   private def compute!
      block_count = (@key_length.to_f / @hash_function.digest_size).ceil.to_u32
      key_io      = IO::Memory.new(@key_length)

      1_u32.upto(block_count) do |block_num|
         key_io.write compute_block(block_num)
      end

      raise "A key of length #{@key_length} was expected, but a key of length #{key_io.size} was computed" unless key_io.size >= @key_length

      @key = key_io.to_slice[0, @key_length]
   end
end
