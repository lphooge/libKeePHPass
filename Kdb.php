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
	
	protected $raw_xml_data = null;
	
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
	
	/**
	 * Return the first group with the given name
	 * 
	 * @param string $name
	 * @return KdbGroup
	 */
	public function getGroupByName($name, $is_regex=false){
		$matches = $this->getGroupsByName($name, $is_regex);
		if(!empty($matches)){
			return reset($matches);
		}
		throw new Exception("Group '$name' not found");
	}
	
	/**
	 * Return all groups with the given name
	 * 
	 * @param string $name
	 * @return KdbGroup
	 */
	public function getGroupsByName($name, $is_regex=false){
		return $this->getGroupsByField('name', $name, $is_regex);
	}
	
	public function getEntryByName($value, $is_regex=false){
		return $this->getEntryByField('name', $value, $is_regex);
	}
	
	public function getEntryByUrl($value, $is_regex=false){
		return $this->getEntryByField('url', $value, $is_regex);
	}
	
	public function getEntryByUsername($value, $is_regex=false){
		return $this->getEntryByField('username', $value, $is_regex);
	}
	
	public function getEntryByField($field, $value, $is_regex=false){
		$es = $this->getEntriesByField($field, $value, $is_regex, true);
		if(count($es) > 0){
			return reset($es);
		}
		throw new Exception("No matching entry found");
	}
	
	/**
	 * Returns all entries where the given field matches the given value
	 * 
	 * @param string $field
	 * @param string $value
	 * @param bool $is_regex treat the value as a perl compatible regular expression
	 * @param bool $firstmatch return only the first match
	 */
	public function getEntriesByField($field, $value, $is_regex=false, $firstmatch=false){
		$available_fields = get_class_vars('KdbEntry');
		if(!in_array($field, $available_fields)){
			throw new Exception("requested field '$field' in Entry does not exist or is not accessible");
		}
		$this->cleanUp();
		$matches = array();
		foreach($this->entry_index as $e){
			
			if($is_regex){
				$match = preg_match($value, $e->$field);
				if($match === false){
					throw new Exception("invalid regular expression");
				}
				$match = (bool) $match;
			} else {
				$match = (bool) ($e->$field == $value);
			} 
			
			if($match){
				$matches[] = $e;
				if($firstmatch){
					return $matches;
				}
			}
		}
		return $matches;
	}
	
	/**
	 * Returns all groups where the given field matches the given value
	 * 
	 * @param string $field
	 * @param string $value
	 * @param bool $is_regex treat the value as a perl compatible regular expression
	 * @param bool $firstmatch return only the first match
	 */
	public function getGroupsByField($field, $value, $is_regex=false, $firstmatch=false){
		$available_fields = get_class_vars('KdbGroup');
		if(!in_array($field, $available_fields)){
			throw new Exception("requested field '$field' in Entry does not exist or is not accessible");
		}
		$this->cleanUp();
		$matches = array();
		foreach($this->group_index as $e){
			
			if($is_regex){
				$match = preg_match($value, $e->$field);
				if($match === false){
					throw new Exception("invalid regular expression");
				}
				$match = (bool) $match;
			} else {
				$match = (bool) ($e->$field == $value);
			} 
			
			if($match){
				$matches[] = $e;
				if($firstmatch){
					return $matches;
				}
			}
		}
		return $matches;
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
		if($header->cipher == KdbHeader::CIPHER_AES){
			$crypt = new KdbCrypt($finalkey, $header->encryptionIV, MCRYPT_MODE_CBC, MCRYPT_RIJNDAEL_128);
		} elseif($header->cipher == KdbHeader::CIPHER_TWOFISH){
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
	
	public function getXml(){
		if($this->raw_xml_data !== null){
			return $this->raw_xml_data;
		}
		throw new Exception("No XML-Data available");
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
		
		$version = false;
		if($header->hasVersion2Signature()){
			$version = 4;
		} elseif($header->hasVersion1Signature()){
			$version = 3;
		} else {
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
		if($version == 4){
			$masterkey = hash('sha256', $masterkey, true); // thanks to the minikeepass source, finally found this this is necessary
		}
		
		$transformed_master_key = self::transformMasterKey($masterkey, $header->transformseed, $header->key_enc_rounds);
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

		// sanity checks
		if(!$this->repair and $version == 3){ // hash check for kdb format...
			$content_hash = hash('sha256', $body, true);
			if($content_hash != $header->content_hash){
				throw new Exception("checksum error, invalid key or currupted data");
			}
		} elseif($version == 4){ // first bytes check for kdbx
			$stream_start = $content_stream->read(32); 
			if($header->stream_start_bytes !== $stream_start){
				throw new Exception("stream start bytes mismatch - wrong credentials?");
			}
		}
		
		// echo "decrypt successfull! <br>";
		
		if($version == 3){
			$this->parseContentV3($content_stream);
		} else {
			$this->parseContentV4($content_stream);
		}

		return $this;
	}
	
	protected function parseContentV4(BinStr $hashed_block_str){
		$unhashed_str = KdbUtil::stripHashedBlocks($hashed_block_str);
		$unhashed_str->rewind();
		$this->raw_xml_data = $unhashed_str->readAll();
	}
	
	protected function parseContentV3(BinStr $content_stream){
		// parse groups
		$header = $this->header;
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
		
		$header->signature1 = KdbHeader::SIG1;
		$header->signature2 = KdbHeader::SIG2_KDB_RELEASE;
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
		$header->transformseed = substr($rnd,32,32);
		
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
		$transformed_master_key = self::transformMasterKey($masterkey, $header->transformseed, $header->key_enc_rounds);
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
