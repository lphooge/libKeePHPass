<?php
/**
 * @author Lutz-Peter Hooge
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt GNU LESSER GENERAL PUBLIC LICENSE
 * @package libKeePHPass
*/
class KdbCrypt{
	protected $mcrypt = null;
	
	protected $mode = null;
	protected $algo = null;
	protected $iv = null;
	
	/**
	 * @param string $key	encryption key
	 * @param string $iv	initialisation vektor, if null an empty IV (null-bytes) is used
	 * @param string $mode 	any of the MCRYPT_MODE_* constants
	 * @param string $algo 	MCRYPT algorithm, like MCRYPT_RIJNDAEL_128, MCRYPT_TWOFISH
	 */
	public function __construct($key, $iv=null, $mode=MCRYPT_MODE_CBC, $algo=MCRYPT_RIJNDAEL_128){
		$this->init($key, $iv, $mode, $algo);
	}
	
	public function __destruct(){
		$this->deinit();
	}
	
	public function test(){
		if(mcrypt_enc_self_test($this->mcrypt) == true){
			throw new Exception("mcrypt self test failed");
		}
	}
	
	public function encrypt($str){
		return mcrypt_generic($this->mcrypt, $str);
	}
	
	public function decrypt($str){
		return mdecrypt_generic($this->mcrypt, $str);
	}
	
	/**
	 * decrypt the string and remove PKCS7 padding
	 * 
	 * @param string $str
	 * @return string
	 */
	public function padDecrypt($str){
		$dec = $this->decrypt($str);
		$strlen = strlen($dec);
		$pad = $dec{$strlen-1};
		$padlen = ord($pad);
		for($i=1;$i<=$padlen; $i++){
			if($dec{$strlen-$i} != $pad){
				throw new Exception("corrupted data: padding error ");
			}
		}
		return substr($dec,0,$strlen-$padlen);
	}
	
	/**
	 * add PKCS7 padding and encrypt the string
	 * 
	 * @param string $str
	 * @return string
	 */
	public function padEncrypt($str){
		$str = (string) $str;
		$padding = 16 - strlen($str) % 16;
		$str .= str_repeat(chr($padding), $padding);
		return $this->encrypt($str);
	}
		
	protected function init($key, $iv=null, $mode=MCRYPT_MODE_CBC, $algo=MCRYPT_RIJNDAEL_128){
		$mcrypt = mcrypt_module_open($algo,null, $mode, null);
		
		if($iv===null){
			$iv = str_repeat("\0",  mcrypt_enc_get_iv_size($mcrypt));
		}
		
		$init_ok = mcrypt_generic_init($mcrypt, $key, $iv);
		if($init_ok !== 0){
			throw new Exception("mcrypt init failed");
		}
			
		if(mcrypt_enc_self_test($mcrypt) == true){
			throw new Exception("mcrypt self test failed");
		}
		
		$this->mcrypt = $mcrypt;
		$this->mode = $mode;
		$this->algo = $algo;
		$this->iv = $iv;
	}
	
	protected function deinit(){
		if(!$this->mcrypt){
			return;
		}
		mcrypt_generic_deinit($this->mcrypt);
		mcrypt_module_close($this->mcrypt);
		$this->mcrypt = null;
		$this->mode = null;
		$this->algo = null;
		$this->iv = null;
	}
}