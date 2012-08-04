<?php
/**
 * @author Lutz-Peter Hooge
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt GNU LESSER GENERAL PUBLIC LICENSE
 * @package libKeePHPass
*/
class KdbEntry {
	
	const TIME_NORMAL = 1072911600; // 1.1.2004 00:00:00
	const TIME_EXPIRE = 66995251199; // 28.12.4092 23:59:59
	
	public $guid = null; ///Unique GUID (database-spanning). Hex 32 Bytes (16 binary)
	public $group_id = 0;
	public $image_id = 0;

	public $name = null;
	public $url = null;
	public $username = null;

	public $password = null; // VARCHAR Password (may be encrypted, see IKpDatabase::UnlockEntryPassword).

	public $notes = null; // notes / additional data

	public $creation_time = self::TIME_NORMAL;
	public $modification_time = self::TIME_NORMAL;
	public $access_time = self::TIME_NORMAL;
	public $expiration_time = self::TIME_EXPIRE;

	public $attachment_desc = null;
	public $attachment = null; // binary string
	
	public function isInternal(){
		return $this->name == "Meta-Info" AND $this->url == '$' AND $this->username == 'SYSTEM';
	}
	
	public function parse($input){ /* @var $input BinaryReader */
		
		if(is_string($input)){
			$input = new BinStr(new StringStream($input));
		}
		
		while(true){
			$position_original = $input->tell();
			$field_type = $input->readUnsignedShort(); //$input->readUnsignedShort(); // 2 bytes
			$field_size = $input->readUnsignedLong(); // 4 bytes
			$value = $input->read($field_size);
			// echo "read file type $field_type length=$field_size, val=".BinStr::toHex($value)." <br>";
			switch($field_type){
				case 0:
					break;
				case 1:
					$this->guid = BinStr::toHex($value);
					break;
				case 2:
					$this->group_id = BinStr::toInt($value);
					break;
				case 3:
					$this->image_id = BinStr::toInt($value);
					break;
				case 4:
					$this->name = trim($value, "\0");
					break;
				case 5:
					$this->url = trim($value, "\0");
					break;
				case 6:
					$this->username = trim($value, "\0");
					break;
				case 7:
					$this->password = trim($value, "\0");
					break;
				case 8:
					$this->notes = trim($value, "\0");
					break;
				case 9:
					$this->creation_time = KdbUtil::unpackTime($value); // acompressedtime
					break;
				case 10:
					$this->modification_time = KdbUtil::unpackTime($value);
					break;
				case 11:
					$this->access_time = KdbUtil::unpackTime($value);
					break;
				case 12:
					$this->expiration_time = KdbUtil::unpackTime($value);
					break;
				case 13:
					$this->attachment_desc = trim($value, "\0");
					break;
				case 14:
					if($field_size != 0){
						$this->attachment = $value;					
					}
					break;
				case 0xFFFF:
					return; // end of Group
				default:
					throw new Exception("unknow field type $field_type");
					break;
			}
		}
		
		return $this;
	}
	
	protected static function writeField($stream,$type,$value){
		$stream->write(BinStr::fromInt($type,2)); // field type
		$stream->write(BinStr::fromInt(strlen($value),4)); // field size
		$stream->write($value);
	}
	
	public function write($stream=null){ /* @var $input BinStr */
		if(!$stream instanceof BinStr){
			$stream = new BinStr(new StringStream($input));
		}
		self::writeField($stream, 1, BinStr::fromHex($this->guid));
		self::writeField($stream, 2, BinStr::fromInt($this->group_id, 4));
		self::writeField($stream, 3, BinStr::fromInt($this->image_id,4));
		self::writeField($stream, 4, $this->name."\0");
		self::writeField($stream, 5, $this->url."\0");
		self::writeField($stream, 6, $this->username."\0");
		self::writeField($stream, 7, $this->password."\0");
		self::writeField($stream, 8, $this->notes."\0");
		self::writeField($stream, 9, KdbUtil::packTime($this->creation_time));
		self::writeField($stream,10, KdbUtil::packTime($this->modification_time));
		self::writeField($stream,11, KdbUtil::packTime($this->access_time));
		self::writeField($stream,12, KdbUtil::packTime($this->expiration_time));
		self::writeField($stream,13, $this->attachment_desc."\0");
		self::writeField($stream,14, $this->attachment);
		self::writeField($stream, 0xFFFF, '');
		return $stream;
	}
}
