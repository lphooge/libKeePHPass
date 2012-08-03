<?php
class FileStream implements Stream {
	protected $handle = null;
	
	public function __construct($filename, $mode='rb'){
		$h = @fopen($filename, $mode);
		if(!$h){
			throw new Exception("could not open file '$filename'");
		}
		$this->handle = $h;
	}
	
	public function __destruct(){
		if($this->handle){
			fclose($this->handle);
		}
	}
	
	public function write($s){
		fwrite($this->handle, $s);
	}
	
	public function truncate(){
		if(!ftruncate($this->handle, 0)){
			throw new Exception("truncating file failed");
		}
	}
	
	public function read($n){
		return fread($this->handle, $n);
	}
	
	public function readAll(){
		ob_start();
		$bytes = @fpassthru($this->handle);
		$content = ob_get_clean();
		if($bytes === false){
			throw new Exception("could not read file");
		}
		return $content;
	}
	
	
	public function seek($n){
		if(!fseek($this->handle, $n)){
			throw new Exception("could not seek to $n");
		}
	}
	
	public function skip($n){
		if(!fseek($this->handle, $n, SEEK_CUR)){
			throw new Exception("could not seek to $n");
		}
	}
	
	public function rewind(){
		rewind($this->handle);
	}
	
	public function tell(){
		return ftell($this->handle);
	}
}
