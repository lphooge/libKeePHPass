<?php
interface Stream {
	function write($n);
	function truncate();
	
	function read($n);
	
	function seek($n);
	function skip($n);
	
	function rewind();
	function tell();
	
	function size();
	
	function eof();
	
	function readAll();
}
