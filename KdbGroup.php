<?php
/**
 * @author Lutz-Peter Hooge
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt GNU LESSER GENERAL PUBLIC LICENSE
 * @package libKeePHPass
*/
class KdbGroup{
	
	const TIME_NORMAL = 1072911600; // 1.1.2004 00:00:00
	const TIME_EXPIRE = 66995251199; // 28.12.4092 23:59:59
	
	public $id = null; // unique (in db) group id
	public $image_id = 0; // index of icon in icon image list
	public $name = null;

	public $creation_time = self::TIME_NORMAL;
	public $modification_time = self::TIME_NORMAL;
	public $access_time = self::TIME_NORMAL;
	public $expiration_time = self::TIME_EXPIRE;

	public $level = 0; // indentation level in the tree.
	public $flags = 0; // default=0, currently not used
	
	
	public $entries = array(); // sub entries
	public $groups = array(); // sub groups
	
	
	public function getEntries(){
		return $this->entries;
	}
	
	public function getGroups(){
		return $this->groups;
	}
	
	public function parse($input){ /* @var $input BinStr */
		
		if(is_string($input)){
			$input = new BinStr(new StringStream($input));
		}
		
		while(true){
			$position_original = $input->tell();
			$field_type = $input->readUnsignedShort(); //$input->readUnsignedShort(); // 2 bytes
			$field_size = $input->readUnsignedLong(); // 4 bytes
			$value = $input->read($field_size);
			//echo "read file type $field_type length=$field_size, val=".BinStr::toHex($value)." <br>";
			switch($field_type){
				case 0:
					// Ignore field
					break;
				case 1:
					$this->id = BinStr::toInt(substr($value,0,4));
					break;
				case 2:
					$this->name = trim($value, "\0");
					break;
				case 3:
					$this->creation_time = Kdb::unpackTime($value); // acompressedtime
					break;
				case 4:
					$this->modification_time = Kdb::unpackTime($value);
					break;
				case 5:
					$this->access_time = Kdb::unpackTime($value);
					break;
				case 6:
					$this->expiration_time = Kdb::unpackTime($value);
					break;
				case 7:
					$this->image_id = BinStr::toInt(substr($value,0,4));
					break;
				case 8:
					$this->level = BinStr::toUInt($value);
					break;
				case 9:
					$this->flags = BinStr::toInt(substr($value,0,4));
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
		self::writeField($stream, 1, BinStr::fromInt($this->id, 4));
		self::writeField($stream, 2, $this->name."\0");
		self::writeField($stream, 3, Kdb::packTime($this->creation_time));
		self::writeField($stream, 4, Kdb::packTime($this->modification_time));
		self::writeField($stream, 5, Kdb::packTime($this->access_time));
		self::writeField($stream, 6, Kdb::packTime($this->expiration_time));
		self::writeField($stream, 7, BinStr::fromInt($this->image_id,4));
		self::writeField($stream, 8, BinStr::fromInt($this->level,2));
		self::writeField($stream, 9, BinStr::fromInt($this->flags,4));
		self::writeField($stream, 0xFFFF, '');
		return $stream;
	}
}
