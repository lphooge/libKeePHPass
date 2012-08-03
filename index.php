<html>
	<head>
		<meta http-equiv="content-type" content="text/html;charset=UTF-8" />
	</head>
<body>
<h1>libKeePHPass: Test and Example page</h1>
<p>
	Place a file named <code>test.kdb</code> encrypted with the password &quot;<i>test</i>&quot; in this directory to run this test!
</p>
<pre>
<?php
try{
	echo "including kdb module...<br/>";
	require_once "Kdb.php";
	
	echo "opening test kdb file...<br/>";
	$db = Kdb::open('test.kdb', 'test');
	
	echo "saving copy...<br/>";
	$db->save('test2.kdb', 'foobar');
	
	echo "reopening copy...<br/>";
	$db = Kdb::open('test2.kdb', 'foobar');

	echo "ok. showing contents...<br/>";
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

<h1>Groups</h1>
<ul>
<?foreach($db->getGroupsIndex() as $group): /* @var $group KdbGroup */ ?>
	<li><?=htmlspecialchars($group->name)?></li>
<?endforeach?>
</ul>

<h1>Entries</h1>
<table border='1'>
	<tr>
		<!-- <th>guid</th>  -->
		<th>name</th>
		<th>url</th>
		<th>username</th>
		<th>password</th>
		<th>created</th>
		<th>modified</th>
		<th>expires</th>
		<th>notes</th>
		<th>attachment description</th>
		<th>attachment</th>
	</tr>
	<?foreach($db->getEntriesIndex() as $entry): /* @var $entry KdbEntry */
		if($entry->isInternal()) // skip internal meta entries
			continue; 
		?>
		<tr>
			<!-- <td><?=htmlspecialchars($entry->guid)?></td>  -->
			<td><?=htmlspecialchars($entry->name)?></td>
			<td><?=htmlspecialchars($entry->url)?></td>
			<td><?=htmlspecialchars($entry->username)?></td>
			<td><?=htmlspecialchars($entry->password)?></td>
			<td><?=date('d.m.Y H:i:s',$entry->creation_time)?></td>
			<td><?=date('d.m.Y H:i:s',$entry->modification_time)?></td>
			<td><?=date('d.m.Y H:i:s',$entry->expiration_time)?></td>
			<td><?=htmlspecialchars($entry->notes)?></td>
			<td><?=htmlspecialchars($entry->attachment_desc)?></td>
			<td>
				<?if($entry->attachment_desc){
					$ext = pathinfo(trim($entry->attachment_desc), PATHINFO_EXTENSION);
					$mime_type = null;
					switch(strtolower($ext)){
						case 'png':
							$mime_type = $mime_type?$mime_type:'image/png';
						case 'jpg':
						case 'jpeg':
							$mime_type = $mime_type?$mime_type:'image/jpeg';
						case 'gif':
							$mime_type = $mime_type?$mime_type:'image/gif';
							$datab64 = base64_encode($entry->attachment);
							echo "<img src='data:$mime_type;base64,$datab64' />";
							break;
						default:
							echo "<pre>".chunk_split(BinStr::toHex($entry->attachment),32)."</pre>";
					}					
				}?>
				
			</td>
		</tr>
	<?endforeach?>
</table>
</body>
</html>
