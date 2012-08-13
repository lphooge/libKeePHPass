<?php
/**
 * @author Lutz-Peter Hooge
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt GNU LESSER GENERAL PUBLIC LICENSE
 * @package libKeePHPass
*/
class KdbHeader {
	
	// Database file signature bytes
	const SIG1_DEF = '03d9a29a';
	const SIG2_DEF = '65fb4bb5';
	
	const SIG1 = '03d9a29a';
	const SIG2_KDB_RELEASE = '65fb4bb5';
	const SIG2_KDBX_PRERELEASE = '66FB4BB5';
	const SIG2_KDBX_RELEASE = '67fb4bb5';
	
	const VERSION_DEF = '03000300';
	const VERSIONX_DEF = '00000300';
	
	const FLAG_SHA2 = 1;
	const FLAG_AES = 2; 
	const FLAG_ARCFOUR = 4; // not used
	const FLAG_TWOFISH = 8;
	
	const CIPHER_AES = 1;
	const CIPHER_TWOFISH = 2;
	
	protected static $CIPHER_UIDS = array(
		self::CIPHER_AES => '31c1f2e6bf714350be5805216afc5aff'
	);
	
	const COMPRESSION_GZIP = 1;
	const COMPRESSION_NONE = 0;
	
	/*
	 * common fields
	 */
	
	public $signature1 = self::SIG1; // file identifier
	public $signature2 = self::SIG2_KDB_RELEASE; // file identifier part 2
	public $version = self::VERSION_DEF;
	
	public $cipher = self::CIPHER_AES;

	public $masterseed = null; // seed for hashing with the user key
	public $encryptionIV = null; // 16 byte initialization vector

	public $transformseed = null; // seed for used for the rounds AES transformations.
	public $key_enc_rounds = 6000; // how often to itererate the master key transformation
	
	public $header_size = 0;
	
	/*
	 * kdbx-specific fields
	 */
	
	public $stream_start_bytes = null; // test string containing the first bytes of decrypted content
	public $compression = self::COMPRESSION_NONE;
	
	/*
	 * kdb-specific fields
	 */
	public $groups = null; // amount of groups
	public $entries = null; //amount of entries

	public $content_hash = null; // hash of the content (minus header and padding) for integrity checking

	/**
	 * Parse a header from a string or stream
	 * 
	 * @param mixed $input
	 */
	public function parse($input){ /* @var $input BinStr */
		if(is_string($input)){
			$input = new BinStr(new StringStream($input));
		}
		$this->signature1 = $input->readHex(4); // 4b
		$this->signature2 = $input->readHex(4); // 4b
		
		if($this->hasVersion1Signature()){
			$this->parseV1($input);
		} elseif($this->hasVersion2Signature()){
			$this->parseV2($input);
		} else {
			throw new Exception("Unknown header structure");
		}
		
		$this->header_size = $input->tell();
	}
	
	/**
	 * parses the kdb-v1 specific parts
	 * 
	 * @param BinStr $input
	 */
	protected function parseV1(BinStr $input){
		$flags = $input->readSignedLong();
		if($flags & self::FLAG_AES){
			$this->cipher = self::CIPHER_AES;
		} elseif($flags & self::FLAG_TWOFISH){
			$this->cipher = self::CIPHER_TWOFISH;
		}
		$this->version = $input->readHex(4); // 4b
		$this->masterseed = $input->read(16); // 16b
		$this->encryptionIV = $input->read(16); // 16b
		$this->groups = $input->readUnsignedLong(); // 4b
		$this->entries = $input->readUnsignedLong(); // 4b
		$this->content_hash = $input->read(32); // 32b
		$this->transformseed = $input->read(32); // 32b
		$this->key_enc_rounds = $input->readUnsignedLong(); // 4b
	}
	
	/**
	 * parses the kdbx-specific parts
	 * 
	 * @param BinStr $input
	 */
	protected function parseV2(BinStr $input){
		$this->version = $input->readHex(4); // 4b
		
		// read header fields in loop
		while(true){
			$field_id = $input->readUnsignedChar();
			$field_size = $input->readUnsignedShort(); // 2 bytes
			$data = $input->read($field_size);
			
			switch($field_id){
				case 0: // EndOfHeader
					break(2);
				case 1:  // Comment
					// debug?
					$this->comment = $data;
					break;
				case 2:  // CipherID
					BinStr::assertLength($data,16);
					$cipher_uuid = BinStr::toHex($data);
					$cipher_id = array_search($cipher_uuid, self::$CIPHER_UIDS);
					if($cipher_id === false){
						throw new Exception("Unknown Cipher UUID $cipher_uuid");
					}
					$this->cipher = $cipher_id;
					break;
				case 3:  // CompressionFlags
					BinStr::assertLength($data,4);
					$this->compression = BinStr::toInt($data); // TODO
					break;
				case 4:  // MasterSeed
					$this->masterseed = $data;
					break;
				case 5:  // TransformSeed
					$this->transformseed = $data;
					break;
				case 6:  // TransformRounds
					BinStr::assertLength($data,8);
					$this->key_enc_rounds = BinStr::toUInt(substr($data,0,4)); // currently only a limited range of encryption rounds is supported
					break;
				case 7:  // EncryptionIV
					$this->encryptionIV = $data;
					break;
				case 8:  // ProtectedStreamKey
					$this->stream_key = $data; // TODO NEW
					break;
				case 9:  // StreamStartBytes
					BinStr::assertLength($data, 32);
					$this->stream_start_bytes = $data;
					break;
				case 10:  // InnerRandomStreamID
					BinStr::assertLength($data,4);
					$this->inner_random_stream_id = BinStr::toInt($data);
					break;
				default:
					continue; // TODO: Warning
			}
		}
	}
	
	/**
	 * writes the header to a stream
	 * 
	 * @param mixed $stream
	 */
	public function write($stream){ /* @var $stream BinStr */
		if(!$stream instanceof BinStr){
			$stream = new BinStr(new StringStream());
		}

		$stream->write(BinStr::fromHex($this->signature1));
		$stream->write(BinStr::fromHex($this->signature2));
		
		if($this->hasVersion2Signature()){
			$this->writeV4($stream);
		} else {
			$this->writeV3($stream);
		}
		$this->header_size = $stream->tell();
	}
	
	protected function writeV3(BinStr $stream){
		$flags = 0;
		if($this->cipher == self::CIPHER_AES){
			$flags |= self::FLAG_AES;
		} elseif($this->cipher == self::CIPHER_TWOFISH){
			$flags |=  self::FLAG_TWOFISH;
		}
		$flags |= self::FLAG_SHA2;
		
		$stream->write(BinStr::fromInt($flags, 4));
		$stream->write(BinStr::fromHex($this->version));
		$stream->write($this->masterseed);
		$stream->write($this->encryptionIV);
		$stream->write(BinStr::fromInt($this->groups, 4));
		$stream->write(BinStr::fromInt($this->entries, 4));
		$stream->write($this->content_hash);		
		$stream->write($this->transformseed);
		$stream->write(BinStr::fromInt($this->key_enc_rounds, 4));
	}

	protected function writeV4(BinStr $stream){
		$stream->write(BinStr::fromHex($this->version));
		
		$this->writeFieldV4($stream, 2, BinStr::fromHex($this->getCipherUUID()));
		$this->writeFieldV4($stream, 3, BinStr::fromInt($this->compression, 4));
		$this->writeFieldV4($stream, 4, $this->masterseed);
		$this->writeFieldV4($stream, 5, $this->transformseed);
		$this->writeFieldV4($stream, 6, BinStr::fromInt($this->key_enc_rounds, 8));
		$this->writeFieldV4($stream, 7, $this->encryptionIV);
		$this->writeFieldV4($stream, 8, $this->stream_key); // TODO: what is this for? generate? just passing through for now
		$this->writeFieldV4($stream, 9, $this->stream_start_bytes);
		$this->writeFieldV4($stream, 10, BinStr::fromInt($this->inner_random_stream_id, 4));
		
		$this->writeFieldV4($stream, 0, BinStr::fromHex('0d0a0d0a')); // EOH
	}
	
	protected function writeFieldV4(BinStr $stream, $field_id, $data){
		$stream->write(BinStr::fromInt($field_id, 1)); // field id
		$stream->write(BinStr::fromInt(strlen($data), 2)); // field length		
		if(strlen($data) > 0){
			$stream->write($data);
		}	
	}
	
	public function getCipherUUID(){
		if(array_key_exists($this->cipher, self::$CIPHER_UIDS)){
			return self::$CIPHER_UIDS[$this->cipher];
		}
	}
	
	/**
	 * Test if this is a kdbx-header
	 * 
	 * @return bool
	 */
	public function hasVersion2Signature(){
		if($this->signature1 == self::SIG1 AND $this->signature2 == self::SIG2_KDBX_PRERELEASE){
			return true;
		}
		if($this->signature1 == self::SIG1 AND $this->signature2 == self::SIG2_KDBX_RELEASE){
			return true;
		}
		return false;
	}
	
	/**
	 * test if this is a kdb (v1) header
	 * @return bool
	 */
	public function hasVersion1Signature(){
		if($this->signature1 == self::SIG1 AND $this->signature2 == self::SIG2_KDB_RELEASE){
			return true;
		}
		return false;
	}
}
