<?php
class StringStream implements Stream {
	protected $str = "";
	protected $ptr = 0;
	
	public function __construct($str=''){
		$this->str = $str;
	}
	
	public function seek($n){
		$this->assertPosValid($n);
		$this->ptr = $n;
		return $this;
	}
	
	public function read($bytes){
		$this->assertPosValid($this->ptr+$bytes);
		$str = substr($this->str, $this->ptr, $bytes);
		$this->ptr += $bytes;
		return $str;
	}
	
	public function readAll(){
		$str = substr($this->str, $this->ptr);
		$this->ptr += strlen($str);
		return $str;
	}
	
	public function skip($bytes){
		$this->assertPosValid($this->ptr+$bytes);
		$this->ptr += $bytes;
		return $this;
	}
	
	public function rewind(){
		$this->seek(0);
		return $this;
	}

	protected function assertPosValid($n){
		if($n < 0 OR $n > strlen($this->str)){
			$range = $n - $this->ptr;
			$x = strlen($this->str) - $this->tell();
			throw new Exception("string pointer out of bounds (tried to get $range bytes, available: $x)");
		}
		return $this;
	}
	
	public function tell(){
		return $this->ptr;
	}
	
	public function write($s){
		$len = strlen($this->str);
		$remaining_len = $len - $this->ptr;
		$add_len = strlen($s);
		
		if($remaining_len == 0){ // append
			$this->str .= $s;
		} else {
			$this->str = substr_replace($this->str, $s, $this->ptr, $add_len);
		}
		$this->ptr+=$add_len;
	}
	
	public function truncate(){
		$this->str = '';
		$this->ptr = 0;
	}
	
	public function size(){
		return strlen($this->str);
	}
	
	public function eof(){
		return $this->ptr >= strlen($this->str);
	}
	
}
