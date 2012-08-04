<?php
class GenericStream implements Stream{
	
	/**
	 * @var Stream
	 */
	protected $stream = null;
	
	public function __construct(Stream $str){
		$this->stream = $str;
	}
	
	function write($n){
		$this->stream->write($n);
	}
	
	function truncate(){
		$this->stream->truncate();
	}
	
	function read($n){
		return $this->stream->read($n);
	}
	
	function readAll(){
		return $this->stream->readAll();
	}
	
	
	function seek($n){
		$this->stream->seek($n);
	}
	
	function skip($n){
		$this->stream->skip($n);
	}
	
	function rewind(){
		$this->stream->rewind();
	}
	
	function tell(){
		return $this->stream->tell();
	}
	
	public function __toString(){
		$pos = $this->tell();
		$this->rewind();
		$str = (string) $this->readAll();
		$this->seek($pos);
		return $str;
	}
}