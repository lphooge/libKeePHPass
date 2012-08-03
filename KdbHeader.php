<?php
/**
 * @author Lutz-Peter Hooge
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt GNU LESSER GENERAL PUBLIC LICENSE
 * @package libKeePHPass
*/
class KdbHeader {
	
	// Database file signature bytes
	const SIG1_DEF = '03d9a29a'; // 0x9AA2D903;
	const SIG2_DEF = '65fb4bb5'; // 0xB54BFB65;
	
	const SIG1_KDBX_PRERELEASE = '03d9a29a'; // 0x9AA2D903;
	const SIG2_KDBX_PRERELEASE = '66FB4BB5'; // 0xB54BFB66;
	const SIG1_KDBX_RELEASE = '03D9A29A'; // 0x9AA2D903;
	const SIG2_KDBX_RELEASE = '67FB4BB5'; // 0xB54BFB67;
	
	const VERSION_DEF = '03000300'; // 0x00030003
	
	const FLAG_SHA2 = 1;
	const FLAG_AES = 2; 
	const FLAG_ARCFOUR = 4;
	const FLAG_TWOFISH = 8;
	
	public $header_size = 0;
	
	public $signature1 = self::SIG1_DEF; // file identifier
	public $signature2 = self::SIG2_DEF; // file identifier part 2
	public $flags = 0;
	public $version = self::VERSION_DEF;

	public $masterseed = null; // seed for hashing with the user key
	public $encryptionIV = null; // 16 byte initialization vector

	public $groups = 0; // amount of groups
	public $entries = 0; //amount of entries

	public $content_hash = null; // hash of the content (minus header and padding) for integrity checking

	public $masterseed2 = null; // seed for used for the rounds AES transformations.
	public $key_enc_rounds = 6000; // how often to itererate the master key transformation
	
	public function parse($input){ /* @var $input BinStr */
		if(is_string($input)){
			$input = new BinStr(new StringStream($input));
		}
		$this->signature1 = $input->readHex(4); // 4b
		$this->signature2 = $input->readHex(4); // 4b
		$this->flags = $input->readSignedLong(); // 4b
		$this->version = $input->readHex(4); // 4b
		$this->masterseed = $input->read(16); // 16b
		$this->encryptionIV = $input->read(16); // 16b
		$this->groups = $input->readUnsignedLong(); // 4b
		$this->entries = $input->readUnsignedLong(); // 4b
		$this->content_hash = $input->read(32); // 32b
		$this->masterseed2 = $input->read(32); // 32b
		$this->key_enc_rounds = $input->readUnsignedLong(); // 4b
		$this->header_size = $input->tell();
	}
	
	public function write($stream){ /* @var $stream BinStr */
		if(!$stream instanceof BinStr){
			$stream = new BinStr(new StringStream());
		}
		$stream->write(BinStr::fromHex($this->signature1));
		$stream->write(BinStr::fromHex($this->signature2));
		$stream->write(BinStr::fromInt($this->flags, 4));
		$stream->write(BinStr::fromHex($this->version));
		$stream->write($this->masterseed);
		$stream->write($this->encryptionIV);
		$stream->write(BinStr::fromInt($this->groups, 4));
		$stream->write(BinStr::fromInt($this->entries, 4));
		$stream->write($this->content_hash);		
		$stream->write($this->masterseed2);
		$stream->write(BinStr::fromInt($this->key_enc_rounds, 4));
		$this->header_size = $stream->tell();
	}
	
	public function hasVersion2Signature(){
		if($this->signature1 == self::SIG1_KDBX_PRERELEASE AND $this->signature2 == self::SIG2_KDBX_PRERELEASE){
			return true;
		}
		if($this->signature1 == self::SIG1_KDBX_RELEASE AND $this->signature2 == self::SIG2_KDBX_RELEASE){
			return true;
		}
		return false;
	}
	
	public function hasVersion1Signature(){
		if($this->signature1 == self::SIG1_DEF AND $this->signature2 == self::SIG2_DEF){
			return true;
		}
		return false;
	}
	
	public function hasFlag($flag){
		return (BinStr::toInt($this->flags) & $flag) != 0; 
	}
}
