rule Weevely_Webshell 
{
	meta:
		description = "Weevely Webshell - Generic Rule - heavily scrambled tiny web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.ehacking.net/2014/12/weevely-php-stealth-web-backdoor-kali.html"
		date = "2014/12/14"
		score = 60
		id = "12aa177a-4ebc-5ed8-a81b-34ec83395ec4"
	strings:
		$s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
		$s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
		$s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
		$s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii
	condition:
		uint32(0) == 0x68703f3c and all of ($s*) and filesize > 570 and filesize < 800
}

rule webshell_h4ntu_shell_powered_by_tsoi_ {
	meta:
		description = "Web Shell - file h4ntu shell powered by tsoi.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "06ed0b2398f8096f1bebf092d0526137"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b"
		$s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui"
		$s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= "
		$s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($"
	condition:
		all of them
}';