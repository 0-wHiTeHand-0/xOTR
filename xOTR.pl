 #!/usr/bin/perl
use strict;
use warnings;
use vars qw($VERSION %IRSSI);

use Irssi;
$VERSION = '0.01';
%IRSSI = (
    authors     => 'Saul A.',
    contact     => 'saul@cryptolab.net',
    name        => 'My First Script',
    description => 'Provide end-to-end strong encryption to IRC groups. ' .
    'You do not need a password, it is generated automaticaly ' .
    'and securely.',
    license     => 'GNU GPLv3'
    );

#use IO::Handle;
#use Crypt::PK::ECC;
#use Crypt::Mode::CTR;
use LWP::UserAgent;
use IPC::Open2;
use Net::SSLeay;
use IO::Socket::SSL;
use MIME::Base64;

use constant NAME => 'plugin';
use constant CA_PATH => '/etc/ssl/certs';
use constant KRISTIAN_SIGN => '0x0B7F8B60E3EDFAE3';
use constant LONGITUD_SIM => 32;#Max = 32
use constant OPENSSL_EC => 'prime256v1';
my $fich = "$ENV{HOME}/Desktop/log.txt";
my $path = Irssi::get_irssi_dir()."/scripts/";
my $pid = 9999;
my @estructura = ();
my $bandera = 0;
#my @share = ();

sub loadconfig{
    open(CONFIG, "<$path".NAME.'_GPG.priv');
    if (!( -f CONFIG)) {
	close(CONFIG);
        if (Net::SSLeay::SSLeay() < 0x1000100f) {
	    Irssi::print('%R-> ERROR: I need openssl-1.0.1 or higher. Update and try again.');
	    error($!);
	    return 1;
	}
	if (system('gpg --version > /dev/null') == 127) {
	    Irssi::print('%R-> ERROR: I need GNU Privacy Guard (gpg). Install gpg and try again.');
	    error($!);
	    return 1;
	}
	Irssi::print('-> GPG keys NOT found, starting load process');
	Irssi::print('-> Downloading SKS CA certificate...');
	#down_file('sks-keyservers.net', '/sks-keyservers.netCA.pem', 'Thawte_Premium_Server_CA.pem','sks-keyservers.netCA.pem');
	Irssi::print('done');
	Irssi::print('-> Downloading SKS CA signature...');
	down_file('sks-keyservers.net', '/sks-keyservers.netCA.pem.asc', 'Thawte_Premium_Server_CA.pem','sks-keyservers.netCA.pem.asc');
	Irssi::print('done');
	Irssi::print('Verifying certificate with signature and Kristian Fiskerstrand (SKS Keyservers pool developer) public key...');
	if (verify_cert() == 0){Irssi::print("Success :)")}
	gen_keys();
	Irssi::print('Generating asymmetric keys...it will take 4 or 5 minutes. This process takes place only once. In the future you won\'t have to wait any more. It is recommended to do anything else with the mouse and the keyboard in order to increase system entropy');
    }else{
	close(CONFIG);
	if (comprueba_keyserver() != 0){
	    actualiza_keyserver();
	    Irssi::timeout_add_once(15000, 'rec_pass', undef)
	}
	else{rec_pass()};
    }
    limpia();
    return 0
}

sub gen_keys{
    my @servers = Irssi::servers();
    for (my $i=0; $i<@servers; $i++){
	llama_gpg(unpack('H*', Net::SSLeay::MD5(substr($servers[$i]->{userhost},0, rindex($servers[$i]->{userhost},'@')).':'.$servers[$i]->{address})));#Crea MD5 de "nick:url_servidor", lo pasa a hexadecimal y llama a GPG para crear el par de claves
	last# De momento solo voy a hacerlo con uno
    }
}

sub llama_gpg{
    my $parametros = "Key-Type: RSA\n";#http://www.ietf.org/rfc/rfc2440.txt
    $parametros .= "Key-Length: 4096\n";
    $parametros .= "Key-Usage: sign\n";# auth\n";
    $parametros .= "Expire-Date: 6m\n";
    $parametros .= 'Name-Real: '.$_[0]."\n";
    $parametros .= 'Name-Comment: '.NAME." crypto engine\n";
    $parametros .= "Preferences: SHA512 SHA384 SHA256 SHA224 CAMELLIA256 AES256 CAMELLIA192 AES192 TWOFISH BZIP2 ZLIB ZIP Uncompressed\n";
    $parametros .= "%pubring $path".NAME."_GPG.publ\n";
    $parametros .= "%secring $path".NAME."_GPG.priv\n";
    $parametros .= "%commit\nsaljoder\n";
    $pid = open2(\*READ, \*WRITE,'gpg','--batch','--gen-key');
    print WRITE $parametros;
    close(WRITE);
    Irssi::pidwait_add($pid)
}

sub limpia{
    my $limpiando = Irssi::active_win();
    my @ventanas = Irssi::windows();
    BUCLE_LIMPIA: for (my $i=0; $i<@ventanas; $i++){
		if ($ventanas[$i]->{refnum} != $limpiando->{refnum}){
			$ventanas[$i]->set_active();
			$limpiando->set_active();
			last BUCLE_LIMPIA
		}
	}
}

sub verify_cert{
    #my $ret = system('gpg','--keyserver','hkps://keys.niif.hu','--keyserver-options','ca-cert='.CA_PATH.'/UTN_USERFirst_Hardware_Root_CA.pem','--recv-keys',KRISTIAN_SIGN);
    my $ret = system('gpg','--keyserver','hkps://keys.fedoraproject.org','--keyserver-options','ca-cert-file='.CA_PATH.'/DigiCert_High_Assurance_EV_Root_CA.pem','--recv-keys',KRISTIAN_SIGN);
    if ($ret != 0){
	Irssi::print('Warning: I could not download public key from "keys.fedoraproject.org". Trying with "key.ip6.li"...');
        $ret = system('gpg','--keyserver','hkps://key.ip6.li','--keyserver-options','ca-cert='.CA_PATH.'/StartCom_Certification_Authority.pem','--recv-keys',KRISTIAN_SIGN);
	#$ret = system('gpg','--keyserver', 'hkps://key.ip6.li', '--recv-keys',KRISTIAN_SIGN);
	if ($ret != 0){
	    Irssi::print('Warning: I could not download public key from "key.ip6.li". Trying with "keys.niif.hu"...');
	    $ret = system('gpg','--keyserver','hkps://keys.niif.hu','--recv-keys',KRISTIAN_SIGN);
	    if ($ret != 0){
		Irssi::print('WARNING: I could not download the public key. I can not verify the certificate.');
		return 1;
	    }
	}
    }
    $ret = system('gpg','--batch','--no-tty','--verify',$path.'sks-keyservers.netCA.pem.asc',$path.'sks-keyservers.netCA.pem');
    if ($ret != 0) {
	imprime_actual("%R--->WARNING: POSSIBLE MAN IN THE MIDDLE ATTACK DETECTED!<--- SKS certificate verification failed");
	return 1
    }
    #$ret = system('gpg', '--batch', '--yes' ,'--delete-key', 'Kristian Fiskerstrand');
    #if ($ret != 0){Irssi::print('ERROR: I could not delete the public key');}
    return 0
}

sub imprime_actual{
if (Irssi::active_win()->{refnum} > 1){Irssi::active_win()->print($_[0])}
Irssi::print($_[0])
}

sub down_file{
    my $client = IO::Socket::SSL->new(
	PeerHost => $_[0],
	PeerPort => 443,
	SSL_version => '!SSLv23:!SSLv2:!SSLv3:!TLSv1:!TLSv1_1',#TLS solo >=1.2
	SSL_verify_mode => SSL_VERIFY_PEER,
	SSL_ca_file => CA_PATH.'/'.$_[2],
	SSL_verifycn_name =>  $_[0],
	SSL_verifycn_scheme => 'http',
	SSL_hostname =>  $_[0]
	) or error($!);
    print $client "GET $_[1] HTTP/1.0\r\nHost: $_[0]\r\nAccept: text/html\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    my @params = <$client>;
    while((index($params[0],'-----BEGIN ') == -1) && (@params>0)){shift(@params)}#Elimina la cabecera HTTP
    open(F,">$path$_[3]");
    print F @params;
    close(F)
}

sub error{
    Irssi::print('%R----> I CAN NOT CONTINUE. ERROR: '.shift.'<----');
    Irssi::command("SCRIPT UNLOAD ".NAME.".pl");
    return 1
}

sub rec_mens{
    my $texto;
    my ($server, $data, $nick, $address) = @_;

    if (!defined($address)){
	$texto="Nuevo DCC de ".$nick.": ".$data."\n\n";
 #   }else{
#	my($dest,$msj)=split(' :',$data,2);
#	if (substr($dest,0,1) eq '#'){###########ES UN CANAL
#	    $texto="Nuevo mensaje de ".$nick." en el canal ".$dest.": ".$msj."\n\n";
#	    Irssi::signal_continue($server, $data." (mensaje recibido en el canal: $dest)", $nick,$address);
#	}else{###############################ES UN PRIVADO
#	    $texto="Nuevo MENSAJE de $nick para $dest: $msj\n\n";
#	    if (substr($data, length($data)-1, 1) eq chr(1)){######## ES UN /me
#		chop($data);
#		$data .= "\n(ME recibido de: $nick)".chr(1);
#	    }else{
#		$data .= "\n(mensaje PRIVADO recibido de: $nick)";
#	    }
#	    Irssi::signal_continue($server, $data, $nick,$address);
#	}
#####################
    }
    my $ac = index($data, ' :'.chr(6));
    if ($ac != -1){
	$ac = substr($data,$ac+3,1);

        if (($ac eq 'A') && (substr($data,0,1) eq '#') && (defined($address))){
	    my $dest = substr($data,0,index($data,' :'));
	  BUCLE_EST6: for (my $i=0; $i<@estructura; $i++){
	      if ($estructura[$i]{_hash} eq $dest.$server->{tag}){
		  if(defined($estructura[$i]{testigo})){
		      manda_priv($server, $nick,'B', $dest);
		      #push @share, {nick=>$nick, sala=>$dest.$server->{tag}, key=>undef};
		      #Añadir temporizador que borre en caso de que tarde
		  }
		  last BUCLE_EST6
	      }
	  }
	    Irssi::signal_stop()

	}elsif(($ac eq 'B') && (substr($data,0,1) ne '#')){ ##Manda clave publica EC, firmada con RSA
	    my $dest = substr($data, index($data,' :')+4);
	    if ((length($dest) != 0) && (substr($dest,0,1) eq '#')){#Canal
		#Eliminar temporizador
	        stop_timeout($dest.$server->{tag})
	    }else{
		Irssi::Irc::Server::query_create($server->{tag},$nick,1);
		my $quer = Irssi::Server::query_find($server->{tag},$nick);
		$quer->print('Encrypting query...wait a moment, please',MSGLEVEL_CLIENTCRAP);
	}
	    my @serv_list = Irssi::servers();
	  BUSCA_SERV: foreach my $i (0..@serv_list-1){
	      if ($serv_list[$i]->{address} eq $server->{address}){
		  $texto = dame_idkey(unpack('H*', Net::SSLeay::MD5(substr($serv_list[$i]->{userhost},0, rindex($serv_list[$i]->{userhost},'@')).':'.$serv_list[$i]->{address})));#ID de clave para firmar
		  my $pkec = Crypt::PK::ECC->new;#Genera par EC
		  $pkec->generate_key(OPENSSL_EC);
		  #Ahora guardo la clave generada
		  if ((length($dest) == 0) || (substr($dest,0,1) ne '#')){$dest = $nick}
		BUCLE_EST1: for (my $j=0; $j<@estructura; $j++){
		    if ($estructura[$j]{_hash} eq $dest.$server->{tag}){
			$estructura[$j]{tempvar} = $pkec;
			last BUCLE_EST1
		    }elsif($j==(@estructura-1)){#No lo ha encontrado. Lo creo.
			push @estructura, {_hash => $dest.$server->{tag}, passwd => undef, testigo => undef, tempvar => $pkec, iv => undef}
		    }
		}
		  $ac = firmar($texto,$pkec->export_key_pem('public'));#Firma la clave publica EC con la clave RSA cuya ID es $texto.
		  $texto = sube_debian($ac);#Devuelve link
		  if ($texto ne '0'){
		      if ($dest eq $nick){$dest = ''}
		      $ac = unpack('H*', Net::SSLeay::RIPEMD160($ac.$texto.$dest.$server->{address})).':'.$texto.':'.$dest.':'.$server->{address};#hash de todo:ID de paste.debian.net:canal/privado:servidor
		      manda_priv($server, $nick,'C', $ac);
		  }
		  last BUSCA_SERV;
	      }
	  }
	    Irssi::signal_stop();

    }elsif(($ac eq 'C') && (substr($data,0,1) ne '#')){
	my @rec_data = split(':',$data,5);
	if ((@rec_data == 5) && (existe_share($nick, $rec_data[3]) == 1)){
	    my $ec_firm = baja_debian($rec_data[2]);
	    if (unpack('H*', Net::SSLeay::RIPEMD160($ec_firm.$rec_data[2].$rec_data[3].$rec_data[4])) eq substr($rec_data[1],2)){
	        #Extraigo la clave publica EC
		$ec_firm = extrae_gpg($ec_firm, $address, $server->{address});
		if ($ec_firm ne '0'){
		    #Cifrar la clave simetrica, y mandar
		    my $dest = $rec_data[3];
		    if ($dest eq ''){$dest = $nick}
		  BUCLE_EST2: for (my $i=0; $i<@estructura; $i++){
		      if ($estructura[$i]{_hash} eq $dest.$server->{tag}){
			  my $pk = Crypt::PK::ECC->new(\$ec_firm);
			  if ($dest eq $nick){$server->print($dest,'Ready :D',MSGLEVEL_CLIENTCRAP)}
			  $dest =  encode_base64($pk->encrypt($estructura[$i]{passwd}.$estructura[$i]{iv}, 'Whirlpool'));#Reutilizo $dest para guardar el criptograma, codificado en base64. Mando clave simetrica + iv
			  manda_priv($server,$nick,'D',$rec_data[3].':'.$dest);
			  last BUCLE_EST2;
		      }
		  }
		}
	    }else{
		imprime_actual("%R--->WARNING: POSSIBLE MAN IN THE MIDDLE ATTACK DETECTED!<--- EC PUBLIC KEY MODIFIED IN PASTEBIN.DEBIAN.NET")
	    }
	}else{
		imprime_actual('WARNING: Somebody is doing bad things in the background')
	    }
	    Irssi::signal_stop()

	}elsif(($ac eq 'D') && (substr($data,0,1) ne '#')){
	    Irssi::signal_stop();
	    my($peer,$dest,$msj)=split(':',$data,3);
	    chop($peer);
	    $dest = substr($dest,2);
	    if (length($dest) == 0){$dest=$nick}
	  BUCLE_EST3: for (my $i=0; $i<@estructura; $i++){
	      if ($estructura[$i]{_hash} eq $dest.$server->{tag}){
		  $msj = decode_base64($msj);
		  $msj = $estructura[$i]{tempvar}->decrypt($msj);
		  $estructura[$i]{passwd} = substr($msj,0,LONGITUD_SIM);
		  $estructura[$i]{iv} = substr($msj,LONGITUD_SIM);
		  $estructura[$i]{tempvar} = undef;
		  $server->print($dest,'Ready :D',MSGLEVEL_CLIENTCRAP);
		  last BUCLE_EST3
	      }
	  }
	}elsif($ac eq 'E'){
	    my($dest,$msj)=split(' :',$data,2);
	    $msj = substr($msj,2);
	    if (substr($dest,0,1) ne '#'){$dest=$nick}
	  BUCLE_EST4: for (my $i=0; $i<@estructura; $i++){
	      if ($estructura[$i]{_hash} eq $dest.$server->{tag}){
		  my $m = Crypt::Mode::CTR->new('Camellia');
		  $data = substr($data,0,index($data,' :')+2);
		  $m = $m->decrypt(decode_base64($msj), $estructura[$i]{passwd}, $estructura[$i]{iv});
		  if ($m eq ''){Irssi::print('ERROR decrypting message!')}
		  else{
			$data .= $m;
			aumenta_iv($estructura[$i]{iv})
		}
		  last BUCLE_EST4
	      }
	  }
	    Irssi::signal_continue($server,$data,$nick,$address);

	}else{
	    Irssi::print('Unknown command received');
	}
	#for (my $i=0; $i<@rec_data; $i++){Irssi::print($rec_data[$i].'<->')}
    }else{
	my $temp = substr($data, 0, index($data,' :')+2);
	$temp .= "\00304INSECURE->\017 ";#Era en octal..!! Maldito sea https://en.wikipedia.org/wiki/C0_and_C1_control_codes
	$temp .= substr($data, index($data,' :')+2);
	Irssi::signal_continue($server,$temp,$nick,$address);
    }
}

sub manda_priv{#Divide los datos para poder mandar mensajes de 440 caracteres (es el limite de irssi), en caso de que se exceda. Si excede, introduce un codigo ascii a continuacion de la letra para poder ordenar los datos en recepcion
    if (int((length($_[3])-1)/438) == 0){#438 caracteres si caben (+ chr(6) + letra)
	$_[0]->command('/^msg -'.$_[0]->{tag}.' '.$_[1].' '.chr(6).$_[2].$_[3]);
	Irssi::print('/^msg -'.$_[0]->{tag}.' '.$_[1].' '.chr(6).$_[2].$_[3]);
    }else{
        my $temp;
	my $i=0;
	do{
	    $temp = chr(6).$_[2].chr($i+48).substr($_[3],437*$i,437);
	    $_[0]->command('/^msg -'.$_[0]->{tag}.' '.$_[1].' '.$temp);
	  Irssi::print("HOLY SHIT: ".'/^msg -'.$_[0]->{tag}.' '.$_[1].' '.$temp);
	    $i++;
	}while(length($temp) == 440);
    }
}

sub actualiza_gpg{
    my $act = system('gpg','--no-tty','--no-default-keyring','--secret-keyring',$path.NAME.'_GPG.priv','--keyring',$path.NAME.'_GPG.publ','--keyserver','hkps://hkps.pool.sks-keyservers.net','--keyserver-options','ca-cert-file='.$path.'sks-keyservers.netCA.pem','--refresh-keys');
    if ($act != 0){error('Error updating GPG keys: '.$!)}
}

sub extrae_gpg{
    open(ARCH, ">>$path".NAME.'_very_temp1.asc') or return 1;
    print ARCH shift;
    close(ARCH);
    my $req = 'gpg --no-default-keyring --secret-keyring '.$path.NAME.'_GPG.priv --keyring '.$path.NAME.'_GPG.publ -o- -d '.$path.NAME.'_very_temp1.asc';
    $req = qx($req);
    if ($? != 0){
	my $u_host = shift;
	$u_host = unpack('H*', Net::SSLeay::MD5(substr($u_host,0, rindex($u_host,'@')).':'.shift));
	my $id = encuentra_id_serv($u_host);
	if ($id ne '1'){
	    $id = recv_key($id);#Devuelve 0 si correcto, codigo de error !=0 si no la encuentra
	    if ($id == 0){
		$req = 'gpg --no-default-keyring --secret-keyring '.$path.NAME.'_GPG.priv --keyring '.$path.NAME.'_GPG.publ -o- -d '.$path.NAME.'_very_temp1.asc';
		$req = qx($req);
		if ($? != 0){
		    imprime_actual("%R--->WARNING: POSSIBLE MAN IN THE MIDDLE ATTACK DETECTED!<--- SIGNATURE VERIFICATION FAILED");
		    $req = '0'
		}
	    }else{
		Irssi::print('PUBLIC KEY NOT FOUND!!! Error: '.$id);
		$req = '0'
	    }
	}else{
	    Irssi::print('ID NOT FOUND!!!');
	    $req = '0'
	}
    }
    limpia();
    unlink $path.NAME.'_very_temp1.asc';
    return $req
}

sub rec_dcc{
    rec_mens($_[0],$_[1],$_[0]->{nick},undef)
}

sub send{
    my ($data, $server, $item) = @_;
    if ((defined($item)) && ($server) && ($server->{connected}) && ($data) && (length($data) > 0) && ((substr($data,0,1) ne '/') || (substr($data,0,4) eq '/me ') || (substr($data,0,8) eq '/action '))){
	Irssi::signal_stop();
	if (substr($data,0,2) ne '! '){
	    if ($bandera == 0){
		imprime_actual('I will notify you when I\'m ready. Meanwhile you can write INSECURELY placing "! " ahead.');
		return
	    }
	    my $m = Crypt::Mode::CTR->new('Camellia');
	  BUCLE_EST5: for (my $i=0; $i<@estructura; $i++){
	      if ($estructura[$i]{_hash} eq $item->{name}.$server->{tag}){
		  if (substr($data,0,1) ne '/'){
		      $m = encode_base64($m->encrypt($data, $estructura[$i]{passwd}, $estructura[$i]{iv}));
		      @_ = ("/^msg", $server, $item->{name}.' '.chr(6).'E'.$m);
#		  }elsif(substr($data,0,5) eq '/msg '){
#		      $data = substr($data,5);
#		      $m = encode_base64($m->encrypt($data, $estructura[$i]{passwd}, $estructura[$i]{iv}));
#		      @_ = ("/^msg", $server, chr(6).'E'.$m);
		  }elsif(substr($data,0,4) eq '/me '){
		      $data = substr($data,4);
		      $m = encode_base64($m->encrypt($data, $estructura[$i]{passwd}, $estructura[$i]{iv}));
		      @_ = ("/^action", $server, $item->{name}.' '.chr(6).'E'.$m);
		  }elsif(substr($data,0,8) eq '/action '){
		      $data = substr($data,8);
		      $m = encode_base64($m->encrypt($data, $estructura[$i]{passwd}, $estructura[$i]{iv}));
		      @_ = ("/^action", $server, chr(6).'E'.$m);
		  }else{
		      ERROR($!);
		      return 1;
		  }
		  aumenta_iv($estructura[$i]{iv});
		  last BUCLE_EST5;
	      }
	  }
	    $server->print($item->{name},'<'.$server->{nick}.'|SECURE> '.$data,MSGLEVEL_CLIENTCRAP);
	}else{
	    @_ = ("/^msg", $server, $item->{name}.' '.substr($data,2));
	    $server->print($item->{name},'<'.$server->{nick}.'|%RINSECURE%n> '.substr($data,2),MSGLEVEL_CLIENTCRAP)
	}
	hidden_send(@_);
    }elsif(($data) && ($data eq '/wc')){
	my $item = Irssi::UI::Window::items(Irssi::active_win())->{name};
	my $servidor = Irssi::active_server()->{tag};
	BUCLE_EST10: for (my $i=0; $i<@estructura; $i++){
	      if ($estructura[$i]{_hash} eq $item.$servidor){
		  splice(@estructura, $i, 1);
		  last BUCLE_EST10
	      }
	}
    }elsif(substr($data,0,5) eq '/msg '){
	Irssi::signal_stop();
	my @temp;
	my $var1;
	if (substr($data,5,1) eq '-'){
	    @temp = split(' ',$data,4);
	    $var1 = $temp[2];
	    $server = Irssi::server_find_tag(substr($temp[1],1))
	}else{
	    @temp = split(' ',$data,3);
	    $var1 = $temp[1]
    }
	$server->command('/^MSG '.$var1.' '.chr(6).'B');
	Irssi::Irc::Server::query_create($server->{tag},$var1,0);
	imprime_actual('Encrypting query...wait a moment, please');
	$temp[0] = crea_pass();
	push @estructura,{_hash => $var1.$server->{tag}, passwd => $temp[0], testigo => undef, tempvar => undef, iv => crea_iv($temp[0])};
    }elsif(substr($data,0,6) eq '/join '){
	Irssi::signal_stop();
	my @temp;
	my $var1;
	if (substr($data,6,1) eq '-'){
	    @temp = split(' ',$data,3);
	    $var1 = $temp[2];
	    $server = Irssi::server_find_tag(substr($temp[1],1))
	}else{
	    @temp = split(' ',$data,2);
	    $var1 = $temp[1]
    }
	Irssi::Irc::Server::query_create($server->{tag},$var1,0);
        $server->print($var1, 'Encrypting channel...wait a moment, please',MSGLEVEL_CLIENTCRAP);
	$server->command('/^MSG '.$var1.' '.chr(6).'A');
	push @estructura,{_hash => $var1.$server->{tag}, passwd => undef, testigo => 0, tempvar => Irssi::timeout_add_once(3000, 'testigo', $var1.chr(0).$server->{tag}.'0')}
    }
}

sub hidden_send{
    my ($com, $server, $data) = @_;
    $server->command("$com -$server->{tag} $data");
}

sub genera_ec{
    my $resp = system('openssl','ecparam','-param_enc','explicit','-name',OPENSSL_EC,'-genkey','-out',$path.NAME.'_'.$_[0].'.pri');
    if ($resp != 0){error('Error creating EC private key: '.$resp)}
    $resp = system('openssl','ec','-in',$path.NAME.'_'.$_[0].'.pri','-pubout','-out',$path.NAME.'_'.$_[0].'.pub');
    if ($resp != 0){error('Error creating EC public key: '.$resp)}
}

sub encuentra_id_serv{#Busca la ID de la clave segun el nombre
    my $client;
    my @resp;
    my @servers = ('key.ip6.li','keys.fedoraproject.org','pgp.mit.edu');
    my @certs = (CA_PATH.'/StartCom_Certification_Authority.pem',CA_PATH.'/DigiCert_High_Assurance_EV_Root_CA.pem',CA_PATH.'/AddTrust_External_Root.pem');
  PR_SERV: for (my $i=0; $i<@servers; $i++){
      $client = IO::Socket::SSL->new(
	  PeerHost => $servers[$i],
	  PeerPort => 443,
	  SSL_version => '!SSLv23:!SSLv2:!SSLv3:!TLSv1:!TLSv1_1',#TLS solo >=1.2
	  SSL_verify_mode => SSL_VERIFY_PEER,
	  SSL_ca_file => $certs[$i],
	  SSL_verifycn_name =>  $servers[$i],
	  SSL_verifycn_scheme => 'http',
	  SSL_hostname => $servers[$i]
	  ) or next PR_SERV;
      print $client "GET /pks/lookup?op=vindex&search=$_[0] HTTP/1.0\r\nHost: $servers[$i]\r\nAccept: text/html\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
      @resp = <$client>;
      while((index($resp[0],'<strong>pub</strong>') == -1) && (@resp>0)){shift(@resp)}
      if (@resp>0){
	  $resp[0] = substr($resp[0], index($resp[0], '</a>')-8, 8);
	  last PR_SERV;
      }else{
	  $resp[0] = '1';
      }
  }
    return $resp[0];
}

sub recv_key{
    my @servers = ('key.ip6.li','pgp.mit.edu','keys.fedoraproject.org');
    my @certs = (CA_PATH.'/StartCom_Certification_Authority.pem',CA_PATH.'/AddTrust_External_Root.pem',CA_PATH.'/DigiCert_High_Assurance_EV_Root_CA.pem');
    my $req;
    BUCLE_SERV: for (my $i=0; $i<@servers; $i++){
	$req = system('gpg','--no-default-keyring','--secret-keyring',$path.NAME.'_GPG.priv','--keyring',$path.NAME.'_GPG.publ','--keyserver','hkps://'.$servers[$i],'--keyserver-options','ca-cert-file='.$certs[$i],'--recv-keys',$_[0]);
	if ($req == 0){last BUCLE_SERV}
    }
    return $req;
}

sub sube_debian{#Irssi trunca los mensajes a 440 caracteres. Como los datos firmados ocupan más, hay que subirlos a un pastebin. Dividirlos y mandar mensajes de 440 caracteres es muy ineficiente.
    my $ua = LWP::UserAgent->new;
    $ua->agent('Opera/9.80 (X11; Linux i686; U; Debian; es) Presto/2.12.388 Version/12.14 ');#El primero que he pillado
    my $req = HTTP::Request->new(POST => 'http://paste.debian.net/server.pl');
    $req->header('content-type' => 'text/xml');
    $req->content('<?xml version="1.0"?>
<methodCall>
<methodName>paste.addPaste</methodName>
<params>
<param>
<value><string>'.shift."\n\n".'</string></value>
</param>
<param>
<value><string>anonymous</string></value>
</param>
<param>
<value><i4>10</i4></value>
</param>
<param>
<value><string></string></value>
</param>
<param>
<value><i4>1</i4></value>
</param>
</params>
</methodCall>');

    $ua = $ua->request($req);#Ahora tengo la respuesta en $ua
    if ($ua->is_success){
        $ua = substr($ua->content, index($ua->content,'<name>id</name><value><string>')+30);
	$ua = substr($ua,0,index($ua,'</string>'));
    }else{
	error('Error uploading key to pastebin.debian.net: '.$ua->status_line);
	$ua='0';
    }
    return $ua;
}

sub baja_debian{
    my $ua = LWP::UserAgent->new;
    $ua->agent('Opera/9.80 (X11; Linux i686; U; Debian; es) Presto/2.12.388 Version/12.14 ');#El primero que he pillado
    my $req = HTTP::Request->new(POST => 'http://paste.debian.net/server.pl');
    $req->header('content-type' => 'text/xml');
    $req->content('<?xml version="1.0"?>
<methodCall>
<methodName>paste.getPaste</methodName>
<params>
<param>
<value><string>'.shift.'</string></value>
</param>
</params>
</methodCall>');
    $ua = $ua->request($req);
    if ($ua->is_success){
        $ua = substr($ua->content, index($ua->content,'<name>code</name><value><string>')+32);
	$ua = substr($ua,0,index($ua,'</string>'));
	chop($ua);
	chop($ua);#Le quito los \n que le meti al final
    }else{
	error('Error uploading key to pastebin.debian.net: '.$ua->status_line);
	$ua='0';
    }
    return $ua;
}

sub comprueba_keyserver{##################FALTA
    return 0;
}

sub dame_idkey{#Se le pasa md5(nick:servidor), y recupera ID de la clave de firmado
    my $indice = 'gpg --no-default-keyring --secret-keyring '.$path.NAME.'_GPG.priv --keyring '.$path.NAME.'_GPG.publ --list-keys';
    $indice = qx($indice);
    #my $i=index($indice, $_[0]);
    my $i=index($indice,"\nuid ");#######Fuerzo a que de la primera que pille. Hay que cambiarlo cuando haya varias claves para varios servidores
    if ($i == -1){error('ERROR recovering GPG public key')}
    $i = rindex($indice, '/',$i);
    return substr($indice, $i+1, 8);
}

sub firmar{
    open(ARCH, ">>$path".'_firm_temp.txt');
    print ARCH $_[1];
    close(ARCH);
    my $peticion = 'gpg --no-default-keyring --secret-keyring '.$path.NAME.'_GPG.priv --keyring '.$path.NAME.'_GPG.publ -a -u '.$_[0].' -o - -s '.$path.'_firm_temp.txt';
    $peticion = qx($peticion);
    ############Hacer algo si caduca la clave
    if (!unlink($path.'_firm_temp.txt')) {error($!)}
    return $peticion;
}

sub actualiza_keyserver{#Actualiza TODAS las claves publicas de firmado, en una peticion
    Irssi::print('Updating keyserver... This will take 15 seconds.');
    my $id_key = 'gpg --no-default-keyring --secret-keyring '.$path.NAME.'_GPG.priv --keyring '.$path.NAME.'_GPG.publ --list-secret-keys';
    $id_key = qx($id_key);
    my $temp = '';
    my $i = index($id_key, "\nsec ");
    while ($i != -1){
	$temp .= substr($id_key, index($id_key, '/', $i)+1, 8).' ';
	$i = index($id_key, "\nsec ", $i+5);
    }
    # Irssi::print('ACTUALIZANDO: '.$temp);
    $id_key = system('gpg','--no-tty','--no-default-keyring','--secret-keyring',$path.NAME.'_GPG.priv','--keyring',$path.NAME.'_GPG.publ','--keyserver','hkps://hkps.pool.sks-keyservers.net','--keyserver-options','ca-cert-file='.$path.'sks-keyservers.netCA.pem','--send-key',$temp);
    if ($id_key != 0){
	Irssi::print('%R-> ERROR: I could not send the public key to the keyserver.');
	error($!);
    }
}

sub shuffle {#Algoritmo Knuth-Durstenfeld de rosettacode.org modificado
    foreach my $n (1 .. $#_) {
	my $k = int rand $n + 1;
	$k == $n or @_[$k, $n] = @_[$n, $k];
    }
}

sub crea_pass{
    my @bytes = (0);
    open ('URAND', '/dev/urandom') or die error($!);
    read ('URAND', $bytes[0], LONGITUD_SIM);
    close('URAND');
    no warnings 'qw';
    my @chars = ('#', qw 'a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 0 1 2 3 4 5 6 7 8 9 ! $ % & ( ) * + , - . / : ; < = > ? @ [ ] ^ _ { | } ~');
    shuffle(@chars);
    my $pass = '';

    @bytes = split(//, $bytes[0]);
    foreach my $i (0..@bytes-1){
	$pass .= $chars[ord($bytes[$i]) % @chars];
    }
    return $pass;
}

sub cont{
    if ($pid != 9999){
	$pid = 9999;
	Irssi::print('Master keys created :)');
	#actualiza_keyserver();
	#Irssi::timeout_add_once(15000, 'rec_pass', undef);
    }
}

sub existe_share{
	return 1;
 #   if ($_[1] eq ''){return 1}
 #   for (my $i=0; $i<@share; $i++){
#	if (($share[$i]{nick} eq $_[0]) && ($share[$i]{sala} eq $_[1])){return 1}
 #   }
    return 0
}

#	    	    my $dest;
#	    if (substr($data,0,1) eq '#'){$dest = substr($data,0,index($data,' :#'))}else{$dest = $nick;}
#	    push @estructura,{_hash => $dest.$server->{tag}, passwd => '', testi#go => 0, tempvar => Irssi::timeout_add_once(3000, 'testigo', $item->{name}.$item->{server}->{tag}.'0')};

sub rec_pass{
    Irssi::print('done');
    my @win = Irssi::windows();
    my $item;
    actualiza_gpg();
    for (my $i=0; $i<@win; $i++){
	$item = Irssi::UI::Window::items($win[$i]);
	if ($item){
	    if ($item->{type} eq "CHANNEL"){
		$item->command('/^MSG '.$item->{name}.' '.chr(6).'A');
		push @estructura,{_hash => $item->{name}.$item->{server}->{tag}, passwd => undef, testigo => 0, tempvar => Irssi::timeout_add_once(3000, 'testigo', $item->{name}.chr(0).$item->{server}->{tag}.'0')};
		$item->print('Encrypting channel...wait a moment, please',MSGLEVEL_CLIENTCRAP);
	    }elsif($item->{type} eq "QUERY"){
		$item->command('/^MSG '.$item->{name}.' '.chr(6).'B');
		$win[0] = crea_pass();
		push @estructura,{_hash => $item->{name}.$item->{server}->{tag}, passwd => $win[0], testigo => undef, tempvar => undef, iv => crea_iv($win[0])};
		$item->print('Encrypting query...wait a moment, please',MSGLEVEL_CLIENTCRAP);
	    }
	}
    }
    $bandera = 1;
}

sub testigo{# Al llamar a esta funcion, meterle al parametro un 0 u otra cosa
    if (chop($_[0]) eq '0'){
	my @comp = split(chr(0), shift, 2);
	my $server = Irssi::server_find_tag($comp[1]);
      SELECT_HASH: for (my $i=0; $i<@estructura; $i++){
	  if ($estructura[$i]{_hash} eq $comp[0].$comp[1]){
	      $estructura[$i]{passwd} = crea_pass();
	      $estructura[$i]{testigo} = 1;
	      $estructura[$i]{tempvar} = undef;
	      $estructura[$i]{iv} = crea_iv($estructura[$i]{passwd});
	      #Irssi::print('Contraseña escogida para '.$_[0].': '.$estructura[$i]{passwd});############QUITAR
	      last SELECT_HASH
	  } 
      }
	$server->print($comp[0],'Ready :D',MSGLEVEL_CLIENTCRAP)
    }
}

sub stop_timeout{
    SELECT_HASH2: for (my $i=0; $i<@estructura; $i++){
	if ($estructura[$i]{_hash} eq $_[0]){
	    Irssi::timeout_remove($estructura[$i]{tempvar});
	    $estructura[$i]{tempvar}=undef;
	    last SELECT_HASH2
	}
    }
}

sub crea_iv{#Tiene que ser longitud 16
    my $a = unpack('H*', Net::SSLeay::MD5(shift));
    my $b = '';
    my $t;
    for (my $i=16; $i<32; $i++){
	$t = substr($a, $i, 1);
	if (ord($t)>57){$b.=chr(ord($t)-49)}
	else{$b.=$t}
    }
    return $b;
}

sub aumenta_iv{
    $_[0]++;
    if ($_[0]>9999999999999999){$_[0]='0000000000000000'}
    else{
	$_[0] = "$_[0]";
	for (my $i=0; $i<16-length($_[0]); $i++){$_[0] = '0'.$_[0]}
    }
}

sub debug{
    my $temp;
    my $temp1;
    for (my $i=0; $i<@estructura; $i++){
	$temp = $estructura[$i]{testigo};
	if (!$temp){$temp = ':*'}
	$temp1 = $estructura[$i]{tempvar};
	if (!$temp1){$temp1 = ':*'};
	Irssi::print("Estructura:\nHash -> ".$estructura[$i]{_hash}.' Password -> '.$estructura[$i]{passwd}.' Testigo -> '.$temp.' Tempvar -> '.$temp1.' IV -> '.$estructura[$i]{iv});
    }
}

Irssi::signal_add_first({
    'event privmsg' => \&rec_mens,
    'dcc chat message' => \&rec_dcc
			});

Irssi::signal_add({
    'send command' => \&send,
    'pidwait' => \&cont
		  });

Irssi::command_bind({
    'enc' => \&loadconfig,
    'con' => \&debug
		    });
