<?php
/**
 * @author Lutz-Peter Hooge
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt GNU LESSER GENERAL PUBLIC LICENSE
 * @package libKeePHPass
 * 
 * this is wrapper class for LibXMLError
*/
class XmlError{
	/**
	 * @var LibXMLError
	 */
	public $libxmlerror = null;
	
	public function __construct(LibXMLError $e){
		$this->libxmlerror = $e;
	}
	
	public function __toString(){
		$e = $this->libxmlerror;
		if(!$e instanceof LibXMLError){
			return "Unknown Error";
		}
		return "$e->message at line $e->line:$e->column";
	}
	
	public static function wrapArray($errors){
		$out = array();
		
		if(is_array($errors)){
			foreach($errors as $e){
				if($e instanceof LibXMLError){
					$out[] = new XmlError($e);
				}
			}
		}
		return $out;
	}
}