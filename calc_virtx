<?php
print "<!--;
Calculadora IP
 -->
  
 <center>
 <form method=\"post\" action=/ferramentas/calculadora-ip>
 <BR><BR>
 <table width=\"95%\" align=center cellpadding=2 cellspacing=2 border=0>
  <tr><td align=\"center\" bgcolor=\"#098D94\">
     <b font color=\"black\" size=\"8px\">Calculadora IP (VirtX)</b>
  </td></tr>
 </table>
 <BR>
 <table>
  <tr>
        <td>Digite IP e Máscara ou CIDR:&nbsp;&nbsp;&nbsp;</td>
        <td><input type=\"text\" name=\"my_net_info\" value=\"\" size=\"31\" maxlength=\"32\"></td>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;<input type=\"submit\" value=\"Calcular\" name=\"subnetcalc\">
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
            &nbsp;</td>
  </tr>
 </table></form><br>";
//Start table
print "<table cellpadding=\"2\">\n<COL span=\"4\" align=\"left\">\n" ;

$end='</table><br><br><table width="95%" align=center cellpadding=2 cellspacing=2 border=0>
      <tr><td bgcolor="#098D94" align=center>Virtx 2014 - Todos os direitos são reservados</td><tr></tr></table></center>';

if (empty($_POST['my_net_info'])){
	tr('Digite IP e CIDR da rede:&nbsp;', '10.0.0.1/22');
	tr('Ou IP e Máscara de rede:','10.0.0.1 255.255.252.0');
	tr('Ou IP e Máscara de rede Coringa:','10.0.0.1 0.0.3.255');
	print $end ;
	exit ;
}

$my_net_info=rtrim($_POST['my_net_info']);


if (! ereg('^([0-9]{1,3}\.){3}[0-9]{1,3}(( ([0-9]{1,3}\.){3}[0-9]{1,3})|(/[0-9]{1,2}))$',$my_net_info)){
	tr("Entrada Inválida.");
	tr('Digite IP e CIDR da rede:&nbsp;', '10.0.0.1/22');
	tr('Ou IP e Máscara de rede:','10.0.0.1 255.255.252.0');
	tr('Ou IP e Máscara de rede Coringa:','10.0.0.1 0.0.3.255');
	print $end ;
	exit ;
}

if (ereg("/",$my_net_info)){  //if cidr type mask
	$dq_host = strtok("$my_net_info", "/");
	$cdr_nmask = strtok("/");
	if (!($cdr_nmask >= 0 && $cdr_nmask <= 32)){
		tr("Valor de CIDR inválido. Tente um inteiro entre 0 - 32.");
		print "$end";
		exit ;
	}
	$bin_nmask=cdrtobin($cdr_nmask);
	$bin_wmask=binnmtowm($bin_nmask);
} else { //Dotted quad mask?
    $dqs=explode(" ", $my_net_info);
	$dq_host=$dqs[0];
	$bin_nmask=dqtobin($dqs[1]);
	$bin_wmask=binnmtowm($bin_nmask);
	if (ereg("0",rtrim($bin_nmask, "0"))) {  //Wildcard mask then? hmm?
		$bin_wmask=dqtobin($dqs[1]);
		$bin_nmask=binwmtonm($bin_wmask);
		if (ereg("0",rtrim($bin_nmask, "0"))){ //If it's not wcard, whussup?
			tr("Máscara de rede inválida.");
			print "$end";
			exit ;
		}
	}
	$cdr_nmask=bintocdr($bin_nmask);
}

//Check for valid $dq_host
if(! ereg('^0.',$dq_host)){
	foreach( explode(".",$dq_host) as $octet ){
 		if($octet > 255){ 
			tr("Endereço IP inválido");
			print $end ;
			exit;
		}
	
	}
}

$bin_host=dqtobin($dq_host);
$bin_bcast=(str_pad(substr($bin_host,0,$cdr_nmask),32,1));
$bin_net=(str_pad(substr($bin_host,0,$cdr_nmask),32,0));
$bin_first=(str_pad(substr($bin_net,0,31),32,1));
$bin_last=(str_pad(substr($bin_bcast,0,31),32,0));
$host_total=(bindec(str_pad("",(32-$cdr_nmask),1)) - 1);

if ($host_total <= 0){  //Takes care of 31 and 32 bit masks.
	$bin_first="N/A" ; $bin_last="N/A" ; $host_total="N/A";
	if ($bin_net === $bin_bcast) $bin_bcast="N/A";
}

//Determine Class
if (ereg('^0',$bin_net)){
	$class="A";
	$dotbin_net= "<font color=\"Green\">0</font>" . substr(dotbin($bin_net,$cdr_nmask),1) ;
}elseif (ereg('^10',$bin_net)){
	$class="B";
	$dotbin_net= "<font color=\"Green\">10</font>" . substr(dotbin($bin_net,$cdr_nmask),2) ;
}elseif (ereg('^110',$bin_net)){
  	$class="C";
	$dotbin_net= "<font color=\"Green\">110</font>" . substr(dotbin($bin_net,$cdr_nmask),3) ;
}elseif (ereg('^1110',$bin_net)){
  	$class="D";
	$dotbin_net= "<font color=\"Green\">1110</font>" . substr(dotbin($bin_net,$cdr_nmask),4) ;
	$special="<font color=\"Green\">Classe D = Endereço de Multicast.</font>";
}else{
  	$class="E";
	$dotbin_net= "<font color=\"Green\">1111</font>" . substr(dotbin($bin_net,$cdr_nmask),4) ;
	$special="<font color=\"Green\">Classe E = Faixa dedicada à experimentos.</font>";
}

if (ereg('^(00001010)|(101011000001)|(1100000010101000)',$bin_net)){
  	 $special='<a href="http://www.ietf.org/rfc/rfc1918.txt">( Consulte a RFC-1918 (Endereços IP privados.)</a>';
}

// Print Results
tr('Descrição','Decimal','Binário');
tr('Endereço:',"<font color=\"blue\">$dq_host</font>",
	'<font color="brown">'.dotbin($bin_host,$cdr_nmask).'</font>');
tr('Máscara de rede:','<font color="blue">'.bintodq($bin_nmask)." = $cdr_nmask</font>",
	'<font color="red">'.dotbin($bin_nmask, $cdr_nmask).'</font>');
tr('Coringa:', '<font color="blue">'.bintodq($bin_wmask).'</font>',
	'<font color="brown">'.dotbin($bin_wmask, $cdr_nmask).'</font>');
tr('Rede:', '<font color="blue">'.bintodq($bin_net).'</font>',
	"<font color=\"brown\">$dotbin_net</font>","<font color=\"Green\">(Classe $class)</font>");
tr('Broadcast:','<font color="blue">'.bintodq($bin_bcast).'</font>',
	'<font color="brown">'.dotbin($bin_bcast, $cdr_nmask).'</font>');
tr('Primeiro Host:', '<font color="blue">'.bintodq($bin_first).'</font>',
	'<font color="brown">'.dotbin($bin_first, $cdr_nmask).'</font>');
tr('Último Host:', '<font color="blue">'.bintodq($bin_last).'</font>',
	'<font color="brown">'.dotbin($bin_last, $cdr_nmask).'</font>');
@tr('Hosts por Rede:', '<font color="blue">'.$host_total.'</font>', "$special");
print "$end";

function binnmtowm($binin){
	$binin=rtrim($binin, "0");
	if (!ereg("0",$binin) ){
		return str_pad(str_replace("1","0",$binin), 32, "1");
	} else return "1010101010101010101010101010101010101010";
}

function bintocdr ($binin){
	return strlen(rtrim($binin,"0"));
}

function bintodq ($binin) {
	if ($binin=="N/A") return $binin;
	$binin=explode(".", chunk_split($binin,8,"."));
	for ($i=0; $i<4 ; $i++) {
		$dq[$i]=bindec($binin[$i]);
	}
        return implode(".",$dq) ;
}

function bintoint ($binin){
        return bindec($binin);
}

function binwmtonm($binin){
	$binin=rtrim($binin, "1");
	if (!ereg("1",$binin)){
		return str_pad(str_replace("0","1",$binin), 32, "0");
	} else return "1010101010101010101010101010101010101010";
}

function cdrtobin ($cdrin){
	return str_pad(str_pad("", $cdrin, "1"), 32, "0");
}

function dotbin($binin,$cdr_nmask){
	// splits 32 bit bin into dotted bin octets
	if ($binin=="N/A") return $binin;
	$oct=rtrim(chunk_split($binin,8,"."),".");
	if ($cdr_nmask > 0){
		$offset=sprintf("%u",$cdr_nmask/8) + $cdr_nmask ;
		return substr($oct,0,$offset ) . "&nbsp;&nbsp;&nbsp;" . substr($oct,$offset) ;
	} else {
	return $oct;
	}
}

function dqtobin($dqin) {
        $dq = explode(".",$dqin);
        for ($i=0; $i<4 ; $i++) {
           $bin[$i]=str_pad(decbin($dq[$i]), 8, "0", STR_PAD_LEFT);
        }
        return implode("",$bin);
}

function inttobin ($intin) {
        return str_pad(decbin($intin), 32, "0", STR_PAD_LEFT);
}

function tr(){
	echo "\t<tr>";
	for($i=0; $i<func_num_args(); $i++) echo "<td>".func_get_arg($i)."</td>";
	echo "</tr>\n";
}
?>
