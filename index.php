<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="content-type" content="text/html;charset=UTF-8" />
		<link rel="stylesheet" type="text/css" charset="utf-8" href="http://ajax.microsoft.com/ajax/jquery.ui/1.8.5/themes/sunny/jquery-ui.css" />
		<script type="text/javascript" charset="utf-8" src="http://ajax.aspnetcdn.com/ajax/jQuery/jquery-1.7.2.min.js"></script>
		<script type="text/javascript" charset="utf-8" src="http://ajax.microsoft.com/ajax/jquery.ui/1.8.5/jquery-ui.min.js"></script>
 		<script type="text/javascript" charset="utf-8" src="http://ajax.aspnetcdn.com/ajax/jquery.dataTables/1.9.2/jquery.dataTables.min.js"></script>
		<link rel="stylesheet" type="text/css" charset="utf-8" href="http://ajax.aspnetcdn.com/ajax/jquery.dataTables/1.9.2/css/jquery.dataTables_themeroller.css" />
 		
 		<script type="text/javascript">
 			$(function(){
  				$('table.kdbtable').dataTable({
  					"bPaginate": false,
					"bJQueryUI": true
				});
  			});
  		</script>
  		<style type="text/css">
			body.ui-widget{
				font-size: 13px;
			}
  		</style>
  		<title>libKeePHPass Example Page</title>
	</head>
	<body class="ui-widget">
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
		<table class="kdbtable">
			<thead>
				<tr>
					<!-- <th>guid</th>  -->
					<th>Group</th>
					<th>Name</th>
					<th>URL</th>
					<th>Username</th>
					<th>Password</th>
					<!-- 
					<th>created</th>
					<th>modified</th>
					 -->
					<th>expires</th>
					<th>Notes</th>
					<th>Attachment</th>
				</tr>
			</thead>
			<tbody>
			<?foreach($db->getEntriesIndex() as $entry): /* @var $entry KdbEntry */
				if($entry->isInternal()) // skip internal meta entries
					continue; 
				?>
				<tr>
					<!-- <td><?=htmlspecialchars($entry->guid)?></td>  -->
					<td><?=htmlspecialchars($db->getGroupById($entry->group_id)->name)?></td>
					<td><?=htmlspecialchars($entry->name)?></td>
					<td><?=htmlspecialchars($entry->url)?></td>
					<td><?=htmlspecialchars($entry->username)?></td>
					<td><?=htmlspecialchars($entry->password)?></td>
					<!--
					<td><?=date('d.m.Y H:i:s',$entry->creation_time)?></td>
					<td><?=date('d.m.Y H:i:s',$entry->modification_time)?></td>
					-->
					<td><?=$entry->expiration_time?date('d.m.Y H:i:s',$entry->expiration_time):''?></td>
					<td><?=htmlspecialchars($entry->notes)?></td>
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
									echo "<img src='data:$mime_type;base64,$datab64' alt='' title='".htmlspecialchars($entry->attachment_desc)."' />";
									break;
								default:
									$tid = uniqid('tgl');
									echo '<a style="cursor:pointer;" title="click to toggle data" onclick="$(\'#'.$tid.'\').toggle();">'.htmlspecialchars($entry->attachment_desc).'</a>';
									echo "<pre class='ui-helper-hidden' id='$tid'>".chunk_split(BinStr::toHex($entry->attachment),32)."</pre>";
								break;
							}					
						}?>
						
					</td>
				</tr>
			<?endforeach?>
			</tbody>
		</table>
	</body>
</html>
