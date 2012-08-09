<?php
class HashStr extends BinStr{
	
	protected $hash = null;
	protected $algo = null;
	protected $himpl = null;
	
	public function __construct(Stream $str, $algo='sha256'){
		parent::__construct($str);
		$this->algo = $algo;
	}
	
	public function startHash(){
		$impl = hash_init($this->algo);
		if(!$impl){
			throw new Exception("could not initialize hash algorithm '$this->algo'");
		}
		$this->himpl = $impl;
	}
	
	protected function breakHash(){
		$this->himpl = null;
	}
	
	/**
	 * returns the current hash
	 */
	public function getHash($raw=true){
		if($this->himpl){
			$himpl_copy = hash_copy($this->himpl);
			$hash = hash_final($this->himpl, $raw);
			$this->himpl = $himpl_copy;
			return $hash;
		}
		throw new Exception("hash is not initialized");
	}
	
	public function read($n){
		$data = parent::read($n);
		$this->updateHash($data);
		return $data;
	}
	
	public function readAll(){
		$data = parent::readAll();
		$this->updateHash($data);
		return $data;
	}
	
	public function write($n){
		parent::write($n);
		$this->updateHash($n);
	}
	

	function truncate(){
		parent::truncate();
		$this->breakHash();
	}
	
	function seek($n){
		parent::seek($n);
		$this->breakHash();
	}
	
	function skip($n){
		$this->read($n);
	}
	
	function rewind(){
		parent::rewind();
		$this->breakHash();
	}
	
	/**
	 * differentially updates the hash if possible
	 * 
	 * @param string $diff
	 */
	protected function updateHash($diff){
		if($this->himpl){
			hash_update($this->himpl, $diff);
		}
	}
}