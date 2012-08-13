<?php
class BinStr extends GenericStream{
	
	// read unsigned
	public function readUnsignedLong(){
		return self::toUInt($this->read(4));
	}
	
	public function readUnsignedShort(){
		return self::toUInt($this->read(2));
	}
	
	public function readUnsignedChar(){
		return self::toUInt($this->read(1));
	}
	
	// read signed
	public function readSignedLong(){
		return self::toInt($this->read(4));
	}
	
	public function readSignedShort(){
		return self::toInt($this->read(2));
	}
	
	public function readSignedChar(){
		return self::toInt($this->read(1));
	}
	
	// write unsigned
	public function writeSignedLong(){
		$this->write(self::toInt(4));
	}
	
	public function writeSignedShort(){
		$this->write(self::toInt(2));
	}
	
	public function writeSignedChar(){
		$this->write(self::toUInt(1));
	}
	
	// write insigned
	public function writeUnsignedLong(){
		$this->write(self::toUInt(4));
	}
	
	public function writeUnsignedShort(){
		$this->write(self::toUInt(2));
	}
	
	public function writeUnsignedChar(){
		$this->write(self::toUInt(1));
	}
	
	/**
	 * Ein Hex Stream wie in einem Hex-Editor (je 2 Zeichen sind eine Hex-Zahl 00-FF, high nibble zuerst)
	 * 
	 * @param int $bytes
	 * return string
	 */
	public function readHex($bytes=1){
		return self::toHex($this->read($bytes));
	}
	
	/**
	 * eine einzelne Hexadezimale Zahl
	 * 
	 * @param int $bytes
	 */
	public function readHexNumber($bytes=1){
		return self::toHexNumber($this->read($bytes));
	}
	
	
	// Static transform helpers
	
	/**
	 * gets an unsigned integer from a binary string assuming little-endian encoding.
	 * this will throw an exeption if the result is to big for php's internal int
	 * 
	 * @param $bin
	 * @return int
	 */
	public static function toUInt($bin){
		$len = strlen($bin);
		if($len > PHP_INT_SIZE){
			throw new Exception("value is too big for type 'int'");
		}
		
		switch($len){
			case 1:
				list(,$int) = unpack('C',$bin); // C = unsigned char
				return $int;
			case 2:
				list(,$int) = unpack('v', $bin); // v = unsigned short (always 16 bit, little endian byte order)
				return $int;
			case 4:
				list(,$int) = unpack('V', $bin); // V = unsigned long (always 32 bit, little endian byte order)
				break;
			default:
				$int = 0;
				for($i=0;$i<$len;$i++){
					$int |= ord($bin{$i}) << $i*8;
				}
				break;
		}
		if($int > PHP_INT_MAX OR $int < 0){
			throw new Exception("value is too big for an unsigned int");
		}
		return $int;
	}
	
	/**
	 * gets an signed integer from a binary string assuming little-endian encoding.
	 * this will throw an exeption if the result is to big for php's internal int
	 * 
	 * @param $bin
	 * @return int
	 */
	public static function toInt($bin){
		$len = strlen($bin);
		if($len > PHP_INT_SIZE){
			throw new Exception("value is too big for type 'int'");
		}
		
		switch($len){
			case 1:
				list(,$int) = unpack('c',$bin); // c = signed char
				return $int;
			default:
				$i = $len - 1;
				$c = ord($bin{$i});
				$first = ($c & 0x80);
				$rest = ($c & ~0x80);
				$int = -$first + $rest;
				for($i=$len-2;$i>=0;$i--){
					$int = $int << 8;
					$c = ord($bin{$i});
					$int |= $c;
				}
		}
		return $int;
	}	

	/**
	 * creates a little-endian binary encoding of the signed int $int with length $len
	 * 
	 * @param $bin
	 * @return int
	 */
	public static function fromInt($int, $len=4){
		$int = (int) $int;
		
		switch($len){
			case 1:
				return pack('c', $int);
			default:
				$bin = '';
				for($i=0;$i<$len;$i++){
					$c = $int % 256;
					$int = $int >> 8;
					$bin .= chr($c); // does accept negative numbers
				}
				if($int > 0){
					throw new Exception("Integer is too big for binary encoding with length $len");
				}
		}
		return $bin;
	}
		
	/**
	 * creates a little-endian binary encoding of the unsigned int $int with length $len
	 * since php only knows signed int, this is only a wrapper that checks if the number is indeed positive
	 * 
	 * @param $bin
	 * @return int
	 */
	public static function fromUInt($int, $len=4){
		if($int < 0){
			throw new Exception("number is not a positive integer");
		}
		self::fromInt($int, $len);
	}
	
	/**
	 * returns the data as a hexadecimal number (significat values first)
	 *  
	 * @param string $bin
	 * @return string
	 */
	public static function toHexNumber($bin){
		list(,$h) = unpack('h*', $bin);
		return strrev($h);
	}
	
	/**
	 * returns the data as a hexadecimal string
	 *  
	 * @param string $bin
	 * @return string
	 */
	public static function toHex($bin){
		list(,$h) = unpack('H*', $bin);
		return $h;
	}
	
	/**
	 * Gets a binay representation of the given hex string
	 * 
	 * @param string $hex
	 * @return string
	 */
	public static function fromHex($hex){
		return pack('H*', $hex);
	}
	
	public static function assertLength($str, $length, $msg="unexpected field size"){
		if(strlen($str) !== $length){
			throw new Exception($msg);
		}
	}
}