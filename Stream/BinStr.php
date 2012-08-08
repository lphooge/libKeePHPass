<?php
class BinStr extends GenericStream{
	
	public function readUnsignedLong(){
		list(,$l) = unpack('L1', $this->read(4));
		if($l < 0){ // can happen if PHP_INT_SIZE = 4
			throw new Exception("Integer overflow: number is too big for unsigned integer");
		}
		return $l;
	}
	
	public function readUnsignedShort(){
		list(,$s) = unpack('S1',$this->read(2));
		return $s;
	}
	
	public function readUnsignedChar(){
		list(,$c) = unpack('C1',$this->read(1));
		return $c;
	}
	
	public function readSignedLong(){
		list(,$l) = unpack('l1',$this->read(4));
		return $l;
	}
	
	/**
	 * Ein Hex Stream wie in einem Hex-Editor (je 2 Zeichen sind eine Hex-Zahl 00-FF, high nibble zuerst)
	 * 
	 * @param int $bytes
	 * return string
	 */
	public function readHex($bytes=1){
		list(,$h) = unpack('H*', $this->read($bytes));
		return $h;
	}
	
	/**
	 * eine einzelne Hexadezimale Zahl
	 * 
	 * @param int $bytes
	 */
	public function readHexNumber($bytes=1){
		list(,$h) = unpack('h*', $this->read($bytes));
		return strrev($h);
	}
	
	
	// Static transform helpers
	
	public static function toUInt($bin){
		switch(strlen($bin)){
			case 1:
				list(,$i) = unpack('C',$bin);
				return $i;
			case 2:
				list(,$i) = unpack('v', $bin);
				return $i;
			case 4:
				list(,$i) = unpack('V', $bin);
				if($i < 0){
					throw new Exception("integer overflow in unsigned long");
				}
				return $i;
			}
		throw new Exception("not implemented for size ".strlen($bin));
	}
	
	public static function toInt($bin){
		$len = strlen($bin);
		
		if(!self::isMachineLittleEndian() AND ($len==2 OR $len==3)){
			throw new Exception("currently not implemented");
		}
		
		switch($len){
			case 1:
				list(,$i) = unpack('c',$bin);
				return $i;
			case 2:
				list(,$i) = unpack('s', $bin);
				return $i;
			case 4:
				list(,$i) = unpack('l', $bin);
				return $i;
		}
		throw new Exception("not implemented for size ".strlen($bin));
	}
	
	public static function fromInt($i, $len){
		switch($len){
			case 1:
				return pack('c', $i);
			case 2:
				return pack('s', $i); // beware of endianness
			case 4:
				return pack('l', $i); // beware of endianness
		}
		throw new Exception("not implemented for size ".$len);
	}
	
	public static function toNumber($bin){
		return hexdec(self::toHexNumber($bin));
	}
	
	public static function toHexNumber($bin){
		list(,$h) = unpack('h*', $bin);
		return strrev($h);
	}
	
	public static function toHex($bin){
		list(,$h) = unpack('H*', $bin);
		return $h;
	}
	
	public static function fromHex($hex){
		return pack('H*', $hex);
	}
	
	private static $_little_endian = null;
	protected static function isMachineLittleEndian() {
		if(self::$_little_endian === null){
    		$i = 0x00FF;
    		$p = pack('S', $i);
    		self::$_little_endian = ($i===current(unpack('v', $p)));
		}
		return self::$_little_endian;
	}
	
	public static function assertLength($str, $length, $msg="unexpected field size"){
		if(strlen($str) !== $length){
			throw new Exception($msg);
		}
	}
}