<?php
if(!defined('SKIP_KEEPHPASS_INCLUDES')){ // define for using autoloader or manual includes
	
	require_once "Stream/Stream.php";
	require_once "Stream/GenericStream.php";
	require_once "Stream/FileStream.php";
	require_once "Stream/StringStream.php";
	require_once "Stream/BinStr.php";
	
	require_once "KdbUtil.php";
	require_once "KdbHeader.php";
	require_once "KdbGroup.php";
	require_once "KdbEntry.php";
	require_once "KdbCrypt.php";
	
}

/**
 * @author Lutz-Peter Hooge
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt GNU LESSER GENERAL PUBLIC LICENSE
 * @package libKeePHPass
*/
class Kdb{
	
	public $repair = false; // open files in relaxed mode and try to correct errors instead of throwing exceptions
	
	protected $is_dirty = false;
	
	/**
	 * @var KdbHeader 
	 */
	protected $header = null;
	
	protected $groups = array(); // array with root groups
	protected $group_index = array(); // index of all groups in this db
	protected $entry_index = array(); // index of all entries in this db
	
	
	public function __construct(){
		$this->header = new KdbHeader();
	}
	
	public function setDirty(){
		$this->is_dirty = true;
	}
	
	protected function cleanUp(){
		if($this->is_dirty){
			$this->refreshIndex();
			$this->is_dirty = false;
		}
	}

	/**
	 * returns the root groups in this database
	 * 
	 * @return array
	 */
	public function getGroups(){
		return $this->groups;
	}
	
	/**
	 * returns an index to all entries in database as an associative array 
	 * 
	 * @return array
	 */
	public function getEntriesIndex(){
		$this->cleanUp();
		return $this->entry_index;
	}
	
	/**
	 * returns an index to all groups in database as an associative array
	 * 
	 * @return array
	 */	
	public function getGroupsIndex(){
		$this->cleanUp();
		return $this->group_index;
	}
	
	/**
	 * rebuilds the group and entry index and the group levels
	 * 
	 * @param KdbGroup $group
	 */
	public function refreshIndex(){
		$this->group_index = array();
		$this->entry_index = array();
		$group_ids_done = array();
		foreach($this->groups as $group){
			if(!$group instanceof KdbGroup){
				throw new Exception("invalid group entry found");
			}
			$group->level = 0;
			$this->refreshIndexForGroup($group, $group_ids_done);
		}
	}
	
	/**
	 * recursively rebuilds the group and entry index and the group levels
	 * 
	 * @param KdbGroup $group
	 * @param array $group_ids_done groups alredy processed
	 */
	protected function refreshIndexForGroup(KdbGroup $group, &$group_ids_done = array()){
		if(in_array($group->id, $group_ids_done)){
			throw new Exception("Group $group->id is referenced multiple times");
		}
		$group_ids_done[] = $group->id;
		
		$this->registerGroup($group);
		foreach($group->getEntries() as $entry){
			if(!$entry instanceof KdbEntry){
				throw new Exception("invalid entry found");
			}
			$this->registerEntry($entry);
		}
		foreach($group->getGroups() as $subgroup){
			if(!$subgroup instanceof KdbGroup){
				throw new Exception("invalid group entry found");
			}
			$subgroup->level = $group->level + 1;
			$this->refreshIndexForGroup($subgroup, $group_ids_done);
		}
	}
	
	/**
	 * Register an entry in this database. Must be added to a group additionally!
	 * 
	 * @param KdbEntry $entry
	 */
	protected function registerEntry(KdbEntry $entry){
		$this->entry_index[$entry->guid] = $entry;
	}
	
	
	/**
	 * Unregister an entry in this database
	 * 
	 * @param KdbEntry $entry
	 */
	protected function unregisterEntry(KdbEntry $entry){
		if(array_key_exists($entry->guid, $this->entry_index)){
			unset($this->entry_index[$entry->guid]);
		}
	}
	
	/**
	 * Register an group in this database. Must be added to a group (or the root groups) additionally!
	 * 
	 * @param KdbGroup $group
	 */
	protected function registerGroup(KdbGroup $group){
		$this->group_index[$group->id] = $group;
	}
	
	/**
	 * unregister an group in this database.
	 * 
	 * @param KdbGroup $group
	 */
	protected function unregisterGroup(KdbGroup $group){
		if(array_key_exists($group->id, $this->group_index)){
			unset($this->group_index[$group->id]);
		}
	}
	
	public function addGroup(KdbGroup $g, KdbGroup $parent=null){
		$this->registerGroup($g);
		if($parent){
			$parent->groups[] = $g;
			$g->level = $parent->level + 1;
			$g->group_id = $parent->id;
		} else {
			$this->groups[] = $g;
			$g->level = 0;
			$g->group_id = null;
		}
		if(!empty($g->entries) or !empty($g->groups)){
			$this->setDirty();
		}
	}
	
	public function addEntry(KdbEntry $e, KdbGroup $parent=null){
		if(!$parent){
			if($e->group_id){
				$parent = $this->getGroupById($e->group_id);
			} elseif($this->groups) { // just add to first group then
				$parent = reset($this->groups);
				$e->group_id = $parent->id;
			} else {
				throw new Exception("no group found for adding entry to");
			}
		}
		
		$this->registerEntry($e);
		$parent->entries[] = $e;
	}
	
	public function removeEntry(KdbEntry $e){
		$parent = $this->getGroupById($e->group_id);
		foreach($parent->entries as $k=>$entry){
			if($entry === $e){
				unset($parent->entries[$k]);
				$this->unregisterEntry($e);
				return;
			}
		}
		throw new Exception("entry was not found in parent group");
	}
	
	
	public function removeGroup(KdbGroup $g){
		$has_subs = !empty($g->entries) or (!empty($g->groups));
		if($g->group_id){
			$parent = $this->getGroupById($g->group_id);
		} else {
			$parent = $this;
		}	
		
		foreach($parent->groups as $k=>$group){
			if($group === $g){
				unset($parent->groups[$k]);
				$this->unregisterGroup($g);
				if($has_subs){
					$this->setDirty();
				}
				return;
			}
		}
		throw new Exception("entry was not found in parent group");
	}
	
	/**
	 * returns the group with the given ID if it is registered in this database
	 * 
	 * @param int $id
	 * @return KdbGroup
	 */
	public function getGroupById($id){
		$this->cleanUp();
		if(!array_key_exists($id, $this->group_index)){
			throw new Exception("requested unknown group no $id");
		}
		$group = $this->group_index[$id];
		if(!$group instanceof KdbGroup){
			throw new Exception("invalid group no $id");
		}
		return $group;
	}
	
	public function getGroupByName($name){
		$this->cleanUp();
		foreach($this->group_index as $g){
			if($g->name == $name){
				return $g;
			}
		}
		throw new Exception("Group '$name' not found");
	}
	
	/**
	 * returns the entry with the given $id if it is registered in this database
	 * 
	 * @param int $id
	 * @return KdbEntry
	 */
	public function getEntryById($guid){
		$this->cleanUp();
		if(!array_key_exists($guid, $this->entry_index)){
			throw new Exception("requested unknown entry no $guid");
		}
		$entry = $this->entry_index[$guid];
		if(!$entry instanceof KdbEntry){
			throw new Exception("invalid entry no $guid");
		}
		return $entry;
	}
	
	/**
	 * Returns the first group in the database
	 * 
	 * @return KdbGroup
	 */
	public function getFirstGroup(){
		if(!empty($this->groups)){
			$first = reset($this->groups);
			return $first;
		}
	}
	
	/**
	 * encrypts the masterkey $rounds times with aes-ecb and the given key, and hashes it with sha256
	 * all strings are in binary (not hex)
	 * 
	 * @param string $masterkey
	 * @param string $key_seed
	 * @param int $rounds
	 * @return string
	 */
	protected static function transformMasterKey($masterkey, $key_seed, $rounds){
		if($key_seed === null){
			return false;
		}
		$transformed_masterkey = $masterkey;
		
		
		$aes = new KdbCrypt($key_seed, null, MCRYPT_MODE_ECB, MCRYPT_RIJNDAEL_128);
		$aes->test();
		
		for($i = 0; $i < $rounds; ++$i){
			$transformed_masterkey = $aes->encrypt($transformed_masterkey);
		}
		unset($aes);
		
		$transformed_masterkey = hash('sha256', $transformed_masterkey, true); // raw binary output
		// echo "Transformed Master key is ".BinStr::toHex($transformed_masterkey);
		return $transformed_masterkey;
	}
	
	/**
	 * Returns en/decryptor object for the body part of the kdb-file
	 * 
	 * @param KdbHeader $header
	 * @param string $finalkey
	 * @return KdbCrypt
	 */
	protected static function getBodyCryptor(KdbHeader $header, $finalkey){
		if($header->hasFlag(KdbHeader::FLAG_AES)){
			$crypt = new KdbCrypt($finalkey, $header->encryptionIV, MCRYPT_MODE_CBC, MCRYPT_RIJNDAEL_128);
		} elseif($header->hasFlag(KdbHeader::FLAG_TWOFISH)){
			$crypt = new KdbCrypt($finalkey, $header->encryptionIV, MCRYPT_MODE_CBC, MCRYPT_TWOFISH);
		} else {
			throw new Exception("Unsupported encryption type");
		}
		unset($finalkey);
		return $crypt;
	}
	
	/**
	 * @param string $filename
	 * @param string $password
	 * @return Kdb
	 */
	public static function open($filename, $password){
		$kdb = new self();
		$kdb->read($filename, $password);
		return $kdb;
	}
	
	/**
	 * opens a kdb file
	 * 
	 * @param string $filename
	 * @param string $password
	 * @return Kdb
	 */
	public function read($filename,$password){
		$header = $this->header;
		
		$input = new BinStr(new FileStream($filename));
		$filesize = filesize($filename); 
		
		try{
			$header->parse($input);
		} catch(Exception $e){
			throw new Exception("Invalid file header");
		}
		
		if($header->hasVersion2Signature()){
			throw new Exception("Unsupported kbdx v2 Format");
		}

		if(!$header->hasVersion1Signature()){
			throw new Exception("Unsupported Format");
		}

		if(substr($header->version,2,6) != substr(KdbHeader::VERSION_DEF,2,6)){
			if(($header->version == '00000200') || ($header->version == '01000200') || ($header->version == '02000200')){
				// self::openDatabaseV2...
				throw new Exception("This version is currently not supported");
			}
			else if(BinStr::toInt($header->version) <= 0x00010002){
				// self::openDatabaseV1...
				throw new Exception("This version is currently not supported");
			}
			else { 
				throw new Exception("This version is currently not supported"); 
			}
		}

		// build key for decrypting
		$masterkey = hash('sha256', $password, true);
		$transformed_master_key = self::transformMasterKey($masterkey, $header->masterseed2, $header->key_enc_rounds);
		if(!$transformed_master_key){
			throw new Exception("generating master key for decrypting failed");			
		}
		$finalkey = hash('sha256',$header->masterseed.$transformed_master_key, true);
		// echo "<br>finalkey (dec)= ".BinStr::toHex($finalkey)."<br>";

		if(!$this->repair){
			if((($filesize - $header->header_size) % 16) != 0){
				throw new Exception("invalid file size!");
			}
		}
		
		$crypt = self::getBodyCryptor($header, $finalkey);
		$body = $crypt->padDecrypt($input->readAll());
		unset($crypt);
		
		$content_size = strlen($body);
		$content_stream = new BinStr(new StringStream($body));
		//echo "decstring is <br><pre>".chunk_split(BinStr::toHex($body),64)."</pre>";
		
		$finalkey = null;

		// Check for success
		if(!$this->repair){
			if(($content_size > 2147483446) || (($content_size == 0) && (($header->groups != 0) || ($header->entries != 0)))){
				throw new Exception("Invalid Key or Error");
			}
		}

		// check if hash matches
		if(!$this->repair){
			$content_hash = hash('sha256', $body, true);
			if($content_hash != $header->content_hash){
				throw new Exception("checksum error, invalid key or currupted data");
			}
		}
		
		// echo "decrypt successfull! <br>";

		// parse groups
		$current_group = 0;
		$groups = array();
		while($current_group < $header->groups){
			$group = new KdbGroup();
			try{
				$group->parse($content_stream);
			} catch(Exception $e){
				echo $e;
				break;
			}
			$groups[] = $group;
			$current_group++;
		}
		
		// build group index and tree
		$group_index = array();
		$root_groups = array();
		$_current_parent = array();
		
		foreach($groups as $group){ /* @var $group KdbGroup */
			$_current_parent[$group->level] = $group;
			
			if(!empty($_current_parent[$group->level - 1])){
				$parent = $_current_parent[$group->level - 1];
			} else {
				$parent = null;
			}
			$this->addGroup($group, $parent);
		}
		// TODO: check levels of groups
		
		// parse entries
		$current_entry = 0;
		$entries = array();
		while($current_entry < $header->entries){
			$entry = new KdbEntry();
			try{
				$entry->parse($content_stream);
			} catch(Exception $e){
				if(!$this->repair){
					throw $e;
				}
				$this->addEntry($entry);
				break;
			}
			$this->addEntry($entry);
			$current_entry++;
		}
		
		return $this;
	}

	/**
	 * Save the database to a file
	  * 
	 * @param string $filename
	 * @param string $password
	 */
	public function save($filename, $password){
		$masterkey = hash('sha256', $password, true);
		
		$this->refreshIndex();
		
		$groups = $this->getGroupsIndex();
		$entries = $this->getEntriesIndex();
		
		$header = $this->header; /* @var $header KdbHeader */
		
		$header->signature1 = KdbHeader::SIG1_DEF;
		$header->signature2 = KdbHeader::SIG2_DEF;
		$header->flags |= KdbHeader::FLAG_SHA2;
		$header->version = KdbHeader::VERSION_DEF;
		
		$header->groups = count($groups);
		$header->entries = count($entries);
		
		if(!$header->key_enc_rounds){
			$header->key_enc_rounds = 6000;
		}
		
		// Make up the master key hash seed and the encryption IV
		$rng_seed = $header->masterseed.$header->encryptionIV.$header->entries;
		$rnd = hash('sha256', uniqid($rng_seed,true),true).hash('sha256', uniqid($rng_seed,true),true); // FIXME: find a better random number source
		
		$header->masterseed = substr($rnd,0,16);		
		$header->encryptionIV = substr($rnd,16,16);
		$header->masterseed2 = substr($rnd,32,32);
		
		$body = new BinStr(new StringStream());
		
		foreach($groups as $group){
			$group->write($body);
		}
		foreach($entries as $entry){
			$entry->write($body);
		}
		
		$header->content_hash = hash('sha256', (string) $body, true);
		
		//echo "output content: <br>";echo "<pre>".chunk_split(binStr::toHex($body),64)."</pre>";
		//echo "<pre>".chunk_split(($body),64)."</pre>";
		
		// generate encryption key
		$transformed_master_key = self::transformMasterKey($masterkey, $header->masterseed2, $header->key_enc_rounds);
		if(!$transformed_master_key){
			throw new Exception("Transforming Master key failed");			
		}
		$finalkey = hash('sha256',$header->masterseed.$transformed_master_key, true);
		
		// echo "finalkey (enc)= ".BinStr::toHex($finalkey)."<br>";
		// echo "iv = ".BinStr::toHex($header->encryptionIV)."<br>";

		// encrypt content
		$crypt = self::getBodyCryptor($header, $finalkey);
		$body_enc = $crypt->padEncrypt((string) $body);
		unset($crypt);
		
		// write file
		$stream = new BinStr(new FileStream($filename, 'w+b'));
		$stream->truncate();
		$header->write($stream);
		$stream->write($body_enc);
		unset($stream);
		
		return true;
	}
}
