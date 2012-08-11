<?php
class Rnd {
	
	protected static $buffer = '';

	/*
	 * returns $n random bytes, tries to use cryptographic strong methods if available
	 * 
	 * @return string
	 */
	public static function read($n){
		if($n > strlen(self::$buffer)){
			self::fillBuffer($n);
		}
		$data = substr(self::$buffer,0,$n);
		self::$buffer = substr(self::$buffer,$n);
		return $data;
	}
	
	/**
	 * Fill the random buffer with at least $n bytes
	 * 
	 * @param int $n
	 */
	protected static function fillBuffer($n){
		$rnd = '';
		// Unix/Linux platform?
		$fp = @fopen('/dev/urandom','rb');
		if ($fp !== FALSE) {
		    $rnd .= @fread($fp,$n);
		    @fclose($fp);
		}
		// MS-Windows platform?
		if (strlen($rnd) < $n AND @class_exists('COM')) {
		    // http://msdn.microsoft.com/en-us/library/aa388176(VS.85).aspx
		    try {
		        $CAPI_Util = new COM('CAPICOM.Utilities.1');
		        $rnd .= $CAPI_Util->GetRandom($n,1);
		    } catch (Exception $ex) {
		    }
		}
		if(strlen($rnd) < $n AND function_exists('openssl_random_pseudo_bytes')){
			$rnd .= openssl_random_pseudo_bytes($n);
		}
		
		while (strlen($rnd) < $n) { // use uniqid hashes as a last resort
			$rnd .= hash('sha256', uniqid(null, true), true);
		}
		self::$buffer .= $rnd;
	}
}
