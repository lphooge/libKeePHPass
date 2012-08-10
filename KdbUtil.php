<?php
/**
 * @author Lutz-Peter Hooge
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt GNU LESSER GENERAL PUBLIC LICENSE
 * @package libKeePHPass
*/
class KdbUtil{
	
	/**
	 * converts a binary kdb-date to unix timestamp
	 * 
	 * @param string $bintime
	 * @return int
	 */
	public static function unpackTime($bintime){
		if(strlen($bintime) < 5){
			throw new Exception("invalid binary time value: ".BinStr::toHex($bintime));
		}
		
		$dw1 = ord($bintime{0});
		$dw2 = ord($bintime{1});
		$dw3 = ord($bintime{2});
		$dw4 = ord($bintime{3});
		$dw5 = ord($bintime{4});
		
		$year = ($dw1 << 6) | ($dw2 >> 2);
		$month = (($dw2 & 0x03) << 2) | ($dw3 >> 6);
		$day = ($dw3 >> 1) & 0x1F;
		$hour = (($dw3 & 0x01) << 4) | ($dw4 >> 4);
		$minute = (($dw4 & 0x0F) << 2) | ($dw5 >> 6);
		$second = $dw5 & 0x03F;
		
		$ts = mktime($hour,$minute,$second,$month,$day,$year);
		return $ts;
	}
	
	/**
	 * converts a unix timestamp to binary kdb-date
	 * 
	 * @param int $time
	 * @return string
	 */
	public static function packTime($time){
		$year = (int) date('Y', $time);
		$month = (int) date('m', $time);
		$day = (int) date('d', $time);
		$hour = (int) date('H', $time);
		$minute = (int) date('i', $time);
		$second = (int) date('s', $time);

		$bytes = str_repeat("\0", 5);
		$bytes{0} = chr(($year >> 6) & 0x3F);
		$bytes{1} = chr((($year & 0x3F) << 2) | (($month >> 2) & 0x03));
		$bytes{2} = chr((($month & 0x03) << 6) | (($day & 0x1F) << 1) | (($hour >> 4) & 0x01));
		$bytes{3} = chr((($hour & 0x0F) << 4) | (($minute >> 2) & 0x0F));
		$bytes{4} = chr((($minute & 0x03) << 6) | ($second & 0x3F));
	
		return $bytes;
	}
	
	/**
	 * decodes and validates hashed block stream, returns clean stream
	 * 
	 * @param BinStr $input
	 * @param BinStr $output
	 * @param bool $validate
	 * @return BinStr
	 */
	public static function stripHashedBlocks(BinStr $input, BinStr $output = null, $validate=true){
		if(!$output){
			$output = new BinStr(new StringStream());
		}
		$buffer_index = 0;
		while(!$input->eof()){
			if($input->readUnsignedLong() !== $buffer_index){
				throw new Exception("invalid data, unexpected block index");
			}
			$buffer_index++;
			$stored_hash = $input->read(32);
			$buffer_size = $input->readUnsignedLong();
			
			if($buffer_size){
				$data = $input->read($buffer_size);
				$hash = hash('sha256', $data, true);
			} else {
				$data = '';
				$hash = str_repeat("\0", 32);
			}
			
			// verify
			if($validate AND $hash !== $stored_hash){
				throw new Exception("invalid data, hash mismatch");
			}
			$output->write($data);
		}
		return $output;
	}
	
	/**
	 * encodes input stream with hashed blocks to output stream
	 * 
	 * @param BinStr $input
	 * @param BinStr $output
	 * @param int blocksize default 1MB
	 * @return BinStr
	 */
	public static function writeHashedBlocks(BinStr $input, BinStr $output = null, $block_size=1048576){
		if(!$output){
			$output = new BinStr(new StringStream());
		}
		$buffer_index = 0;
		while(true){
			$data = $input->read($block_size);
			$buffer_size = strlen($data);
			$hash = $buffer_size>0?hash('sha256', $data):str_repeat("\0",32);
			
			$output->write(BinStr::fromInt($buffer_index,4));
			$output->write($hash);
			$output->write($buffer_size);
			$output->write($data);
			
			$buffer_index++;
		}
		return $output;
	}
}