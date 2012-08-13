<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="content-type" content="text/html;charset=UTF-8" />
  		<title>libKeePHPass Test Page</title>
	</head>
	<body class="ui-widget">
		<h1>libKeePHPass: Tests</h1>
		<b><a href='tests.php'>retry tests</a></b>
	<pre><?php
	try{
		echo "including kdb module...";
		require_once "Kdb.php";
		
		echo "<h2>kdbx Tests</h2>";
		$start = microtime(true);
		
		$tests = array(
			array('file' => 'tests/test_pwd.kdbx', 'pwd' => 'test', 'keyfile' => false),
			array('file' => 'tests/test_pwd_gz.kdbx', 'pwd' => 'test', 'keyfile' => false),
			array('file' => 'tests/test_pwd_plainkeyfile.kdbx', 'pwd' => 'test', 'keyfile' => 'tests/keyfile.plain'),
			array('file' => 'tests/test_pwd_keyfile.kdbx', 'pwd' => 'test', 'keyfile' => 'tests/keyfile.xml'),
			array('file' => 'tests/test_keyfile.kdbx', 'pwd' => false, 'keyfile' => 'tests/keyfile.xml'),
		);
		
		foreach($tests as $test){
			try{
				echo "opening {$test['file']}...";
				$db = Kdb::open($test['file'], $test['pwd'], $test['keyfile']);
				$original_data = $db->getXml();
				echo " saving..";
				$db->save('tests/temp.kdbx', $test['pwd'], $test['keyfile']);
				echo " reopening..";
				$db = Kdb::open('tests/temp.kdbx', $test['pwd'], $test['keyfile']);
				if($db->getXml() != $original_data){
					throw new Exception("data has changed");
				} 
				echo " <span style='color: green'>passed</span>";
			} catch(Exception $e){
				echo "<span title='".htmlspecialchars($e, ENT_QUOTES)."' style='color: red'>failed</span>";
			}
			echo "<br/>";
		}
		unlink('tests/temp.kdbx');
		
		echo "<h2>kdb Tests</h2>";
		
		$tests = array(
			array('file' => 'tests/test_pwd.kdb', 'pwd' => 'test', 'keyfile' => false),
			array('file' => 'tests/test_pwd_twofish.kdb', 'pwd' => 'test', 'keyfile' => false),
			array('file' => 'tests/test_plainkeyfile.kdb', 'pwd' => false, 'keyfile' => 'tests/keyfile.plain'),
			array('file' => 'tests/test_pwd_plainkeyfile.kdb', 'pwd' => 'test', 'keyfile' => 'tests/keyfile.plain'),
			array('file' => 'tests/test_pwd_keyfile.kdb', 'pwd' => 'test', 'keyfile' => 'tests/keyfile.hex'),
		);
		
		foreach($tests as $test){
			try{
				echo "opening {$test['file']}...";
				$db = Kdb::open($test['file'], $test['pwd'], $test['keyfile']);
				echo " saving..";
				$db->save('tests/temp.kdb', $test['pwd'], $test['keyfile']);
				echo " reopening..";
				$db = Kdb::open('tests/temp.kdb', $test['pwd'], $test['keyfile']);
				echo " <span style='color: green'>passed</span>";
			} catch(Exception $e){
				echo "<span title='".htmlspecialchars($e, ENT_QUOTES)."' style='color: red'>failed</span>";
			}
			
			echo "<br/>";
		}
		unlink('tests/temp.kdb');
		
		$time = microtime(true)- $start;
		echo "<p>tests took $time seks</p>";
	} catch(Exception $e){
		echo "</pre>";
		?>
		<h2>Ooops...</h2>
		I encoutered the following error: <b><?=$e->getMessage()?></b>
		<p>Backtrace:</p>
		<pre><?=$e?></pre>
		<?php
		echo "</body></html>";exit();
	}
	?>
	</pre>
	</body>
</html>
