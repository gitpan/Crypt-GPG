# -*-cperl-*-
#
# Crypt::GPG - An Object Oriented Interface to GnuPG.
# Copyright (c) 2000-2001 Ashish Gulhati <hash@netropolis.org>
#
# All rights reserved. This code is free software; you can
# redistribute it and/or modify it under the same terms as Perl
# itself.
#
# $Id: GPG.pm,v 1.25 2001/11/11 14:53:49 cvs Exp $

package Crypt::GPG;

use Carp;
use Fcntl;
use Expect;
use strict;
use Date::Parse;
use POSIX qw( tmpnam );
use Time::HiRes qw( sleep );
use vars qw( $VERSION $AUTOLOAD );

( $VERSION ) = '$Revision: 1.25 $' =~ /\s+([\d\.]+)/;

sub new {
  bless { GPGBIN         =>   'gpg',
	  FORCEDOPTS     =>   '--no-secmem-warning',
	  GPGOPTS        =>   '--lock-multiple --compress-algo 1 --cipher-algo cast5 --force-v3-sigs',
	  VERSION        =>   "Version: Crypt::GPG v$VERSION\n",
	  DELAY          =>   0,
	  PASSPHRASE     =>   '',
	  COMMENT        =>   '',
	  ARMOR          =>   1,
	  DETACH         =>   1,
	  ENCRYPTSAFE    =>   1,
	  TEXT           =>   1,
	  SIGNFIRST      =>   1,
	  SECRETKEY      =>   '',
	  DEBUG          =>   0,
	  VKEYID         =>   '^.*$',
	  VRCPT          =>   '^.*$',
	  VPASSPHRASE    =>   '^.*$',
	  VNAME          =>   '^[a-zA-Z][\w\.\s\-\_]+$',
	  VEXPIRE        =>   '^\d+$',
	  VKEYSZ         =>   '^\d+$',
	  VKEYTYPE       =>   '^ELG-E$',
	  VTRUSTLEVEL    =>   '^[1-4]$',
	  VEMAIL         =>   '^[\w\.\-]+\@[\w\.\-]+\.[A-Za-z]{2,3}$'
	}, shift;
}

sub sign {
  my $self = shift; my ($secretkey, $detach, $armor) = (); my $tmpnam;
  return unless $secretkey =~ /$self->{VKEYID}/ and $self->{PASSPHRASE} =~ /$self->{VPASSPHRASE}/;
  $detach = '-b' if $self->{DETACH}; $armor = '-a' if $self->{ARMOR}; 
  $secretkey = '--default-key ' . "'" . $self->{SECRETKEY} . "'" if $self->{SECRETKEY};
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  my $message = join ('', @_); $message .= "\n" unless $message =~ /\n$/s;
  print FH $message; close FH; 
  my @opts = (split (/\s+/, $self->{FORCEDOPTS}), split (/\s+/, $self->{GPGOPTS}));
  my $expect = Expect->spawn ($self->{GPGBIN}, @opts, '-o-', '--sign', $armor, $detach, 
			      '--default-key', $self->{SECRETKEY}, $tmpnam);
  $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, 'passphrase:');
  sleep ($self->{DELAY}); print $expect "$self->{PASSPHRASE}\r";
  $expect->expect (undef, '-re', '-----BEGIN', 'passphrase:');
  if ($expect->exp_match_number == 2) {
    sleep ($self->{DELAY}); print $expect "$self->{PASSPHRASE}\r";
    $expect->expect (undef, 'passphrase:');
    sleep ($self->{DELAY}); print $expect "$self->{PASSPHRASE}\r";    
    sleep ($self->{DELAY}); $expect->expect (undef);
    unlink $tmpnam; return;
  }
  sleep ($self->{DELAY}); $expect->expect (undef); my $info = $expect->exp_match() . $expect->exp_before(); 
  unlink $tmpnam;
  $info =~ s/\r//sg; $info =~ s/^Version:.*\n/$self->{VERSION}/m; 
  $info =~ s/^Comment:.*\n/$self->{COMMENT}/m; $info=~s/PGP MESSAGE/PGP SIGNATURE/sg;
  return $info;
}

sub decrypt { shift->verify(@_); }

sub verify {
  my $self = shift; my $tmpnam; my $tmpnam2; my $tmpnam3;
  return unless $self->{PASSPHRASE} =~ /$self->{VPASSPHRASE}/;
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  do { $tmpnam2 = tmpnam() } until sysopen(FH2, $tmpnam2, O_RDWR|O_CREAT|O_EXCL);

  my $message = ref($_[0]) ? join '', @{$_[0]} : $_[0];
  $message .= "\n" unless $message =~ /\n$/s;

  print FH $message; close FH;
  if ($_[1]) {
    my $realmessage = join '', @{$_[1]};
    do { $tmpnam3 = tmpnam() } until sysopen(FH3, $tmpnam3, O_RDWR|O_CREAT|O_EXCL);
    $realmessage =~ s/\n/\r\n/sg;
    print FH3 $realmessage; close FH3;
  }
  my $opts = "$self->{FORCEDOPTS} $self->{GPGOPTS}";
  my $expect = Expect->spawn ("$self->{GPGBIN} $opts --yes --decrypt -o $tmpnam2 $tmpnam"); 
  $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, '-re', '^gpg:', '-re', 'passphrase:\s*', '-re', 'data file:');
  if ($expect->exp_match_number==3) {
    sleep ($self->{DELAY}); print $expect "$tmpnam3\r";
    $expect->expect (undef, '-re', 'gpg:', '-re', 'passphrase:\s*');
  }
  if ($expect->exp_match_number==2) {
    sleep ($self->{DELAY}); print $expect "$self->{PASSPHRASE}\r";
    $expect->expect (undef, '-re', 'gpg: encrypted', '-re', 'passphrase:\s*');
    close FH2, close $expect, unlink ($tmpnam, $tmpnam2), return if $expect->exp_match_number()==2;
  }
  sleep ($self->{DELAY}); $expect->expect (undef); 
  my $info = $expect->exp_match() . $expect->exp_before(); 
  unlink $tmpnam; unlink $tmpnam3 if $_[1];
  $info =~ s/\r//sg;
  my $trusted = ($info !~ /WARNING: This key is not certified/s);
  my $unknown = ($info =~ /Can't check signature: public key not found/s);
  $message = join ('',<FH2>); close FH2; unlink ($tmpnam2);
  return ($message) 
    unless $info =~ /.*Signature\ made\ ((?:\S+\s+){6})using\ \S+\ key\ ID\ (\S+)
	             \s*gpg:\ (Good|BAD)\ signature\ from/sx;;
  my $signature = {'Validity' => $3, 'KeyID' => $2, 'Time' => $1, 'Trusted' => $trusted};
  $signature->{Time} =~ s/\S+\s*$//; $signature->{Time} = str2time ($signature->{Time}, $1); 
  bless $signature, 'Crypt::GPG::Signature';
  return ($message, $signature);
}

sub msginfo {
  my $self = shift; my @return = (); my $tmpnam; 
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  print FH join '',@{$_[0]}; close FH; 
  my $opts = "$self->{FORCEDOPTS} $self->{GPGOPTS}";
  my $expect = Expect->spawn ("$self->{GPGBIN} $opts --batch $tmpnam"); 
  $expect->log_stdout($self->{DEBUG});
  sleep ($self->{DELAY}); $expect->expect (undef); my $info = $expect->exp_before();
  $info =~ s/key, ID (.{8})/{push @return, $1}/sge; unlink $tmpnam;
  return @return;
}

sub encrypt {
  my $self = shift; my $info = ''; my $tmpnam; my ($message, $rcpts) = @_;
  my $sign = ''; 
  while( $#_ > 1 ) { 
    my $parm = pop; 
    $sign = '--sign' if $parm eq '-sign';
  }
  my $armor = $self->{ARMOR} ? '-a' : '';
  my @rcpts;
  if (ref($rcpts) eq 'ARRAY') {
    @rcpts = map { return unless /$self->{VRCPT}/; ('-r', /\s/ ? "'$_'" : $_) } @$rcpts;
  }
  else {
    return unless $rcpts =~ /$self->{VRCPT}/;
    @rcpts = ('-r', $rcpts =~ /\s/ ? "'$rcpts'" : $rcpts);
  }
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  $message = join ('', @$message) if ref($message) eq 'ARRAY'; 
  print FH $message; close FH;

  my @opts = (split (/\s+/, $self->{FORCEDOPTS}), split (/\s+/, $self->{GPGOPTS}));
  push (@opts, ('--comment', $self->{COMMENT})) if $self->{COMMENT};
  my $expect = Expect->spawn("$self->{GPGBIN} @opts -o- --encrypt $sign $armor @rcpts $tmpnam");
      
  $expect->log_stdout($self->{DEBUG});
  while (1) {
    my ($pos, $err, $matched, $before, $after) = $expect->expect 
      (undef, '-re', '-----BEGIN PGP', 'Use this key anyway?', 'key not found');
    return if $err;
    if ($pos==2) {
      sleep ($self->{DELAY});
      if ($self->{ENCRYPTSAFE}) {
	print $expect "n\n"; $expect->expect (undef); return undef;
      }
      else {
	print $expect "y\n";
      }	
    }
    elsif ($pos==3) {
      unlink $tmpnam, return undef;
    }
    else {
      $info = $matched;
      last;
    }
  }
  sleep ($self->{DELAY}); $expect->expect (undef);
  $info .= $expect->exp_before(); $info =~ s/.*\n(-----BEGIN)/$1/s;
  $info =~ s/\r//sg; $info =~ s/^Version:.*\n/$self->{VERSION}/m; 
  unlink $tmpnam;
  return $info;
}

sub addkey {
  my $self = shift; my $key = shift; my $pretend = shift; my (@ret, $tmpnam, $tmpnam2, $tmpnam3);
  return unless ref($key) eq 'ARRAY';
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  print FH (join '', @{$key}); close FH;
  do { $tmpnam2 = tmpnam() } until sysopen(FH2, $tmpnam2, O_RDWR|O_CREAT|O_EXCL);
  do { $tmpnam3 = tmpnam() } until sysopen(FH3, $tmpnam3, O_RDWR|O_CREAT|O_EXCL);

  my @pret = ('--options', '/dev/null', '--no-default-keyring', 
	      '--keyring', $tmpnam2, '--secret-keyring', $tmpnam3);
  my @opts = (split (/\s+/, $self->{FORCEDOPTS}), split (/\s+/, $self->{GPGOPTS}));
  my @listopts = qw(--fingerprint --fingerprint --with-colons);
	      
  my @info = backtick($self->{GPGBIN}, @opts, @pret, '-v', '--import', $tmpnam);
  my @keylist = backtick($self->{GPGBIN}, @opts, @pret, '--check-sigs', @listopts); 
  my @seclist = backtick($self->{GPGBIN}, @opts, @pret, '--list-secret-keys', @listopts);
  close FH2, close FH3; unlink $tmpnam2, "$tmpnam2~", $tmpnam3;
  @ret = $self->parsekeys (@keylist[2..$#keylist], @seclist[2..$#seclist]);

  unless ($pretend) {
    my @info = backtick($self->{GPGBIN}, @opts, '-v', '--import', $tmpnam);    
  }
  unlink $tmpnam;
  return @ret;
}

sub export {
  my $self = shift; my $key = shift; my $armor; $armor = "-a" if $self->{ARMOR}; 
  my $id = $key->{ID}; return unless $id =~ /$self->{VKEYID}/;
  my $secret = $key->{Type} eq 'sec' ? '-secret-keys' : '';
  my @opts = (split (/\s+/, $self->{FORCEDOPTS}), split (/\s+/, $self->{GPGOPTS}));
  my @info = backtick($self->{GPGBIN}, @opts, "--export$secret", $armor, $id);
  my $info = join '',@info;
  $info =~ s/\r//sg; $info =~ s/^Version:.*\n/$self->{VERSION}/m; 
  $info =~ s/^Comment:.*\n/$self->{COMMENT}/m;
  return $info;
}

sub keygen {
  my $self = shift; my ($name, $email, $keytype, $keysize, $expire, $pass) = @_;
  return unless $keysize =~ /$self->{VKEYSZ}/ and $keysize > 767 and $keysize < 4097
    and $keytype =~ /$self->{VKEYTYPE}/ and $name =~ /$self->{VNAME}/ and length ($name) > 4
      and $expire =~ /$self->{VEXPIRE}/ and $email =~ /$self->{VEMAIL}/
        and $pass =~ /$self->{VPASSPHRASE}/;
  my $bigkey = ($keysize > 1536);   
  my @opts = (split (/\s+/, $self->{FORCEDOPTS}), split (/\s+/, $self->{GPGOPTS}));
  my $discard = backtick ($self->{GPGBIN}, @opts, '--no-tty', '--gen-random', 0, 1);
  $discard = backtick ($self->{GPGBIN}, @opts, '--no-tty', '--gen-random', 0, 1);
  my $pid = open(GPG, "-|");
  return undef unless (defined $pid);
  if ($pid) {
    $SIG{CHLD} = 'IGNORE';
    return \*GPG;
  }
  else {
    my $opts = "$self->{FORCEDOPTS} $self->{GPGOPTS}";
    my $expect = Expect->spawn ("$self->{GPGBIN} $opts --gen-key"); $expect->log_stdout(0);
    $expect->expect (undef, 'selection?'); sleep ($self->{DELAY}); print $expect ( "1\r"); print ".\n";
    $expect->expect (undef, 'do you want?'); sleep ($self->{DELAY}); print $expect ("$keysize\r"); print ".\n";
    $expect->expect (undef, 'keysize?'), sleep ($self->{DELAY}), print $expect ("y\r"), print ".\n" if $bigkey;
    $expect->expect (undef, 'valid for?'); sleep ($self->{DELAY}); print $expect ("$expire\r"); print ".\n";
    $expect->expect (undef, '(y/n)?'); sleep ($self->{DELAY}); print $expect ("y\r"); print ".\n";
    $expect->expect (undef, 'name:'); sleep ($self->{DELAY}); print $expect ("$name\r"); print ".\n"; 
    $expect->expect (undef, 'address:'); sleep ($self->{DELAY}); print $expect ("$email\r"); print ".\n";
    $expect->expect (undef, 'Comment:'); print $expect ("\r"); print ".\n";
    $expect->expect (undef, 'uit?'); sleep ($self->{DELAY}); print $expect ("o\r"); print ".\n";
    $expect->expect (undef, 'phrase: '); sleep ($self->{DELAY}); print $expect ("$pass\r"); print ".\n";
    $expect->expect (undef, 'phrase: '); sleep ($self->{DELAY}); print $expect ("$pass\r"); print ".\n";
    $expect->expect (undef, '-re', '([\+\.\>\<\^]|created and signed)');
    my $x = $expect->exp_match(); 
    while ($x !~ /created and signed/) {
      print "$x\n";
      my $t = $expect->expect (1, '-re', '([\+\.\>\<\^]|created and signed)');
      $x = $expect->exp_match();
    }	
    print "|\n";
    sleep ($self->{DELAY}); $expect->expect (undef, 'nothing.');
    exit();
  }
}

sub backtick {
  use English; my @ret;
  die "Can't fork: $!" unless defined(my $pid = open(KID, "-|"));
  if ($pid) {           # parent
    while (<KID>) {
      push(@ret, $_);
    }
    close KID;
  } 
  else {
    my @temp     = ($EUID, $EGID);
    my $orig_uid = $UID;
    my $orig_gid = $GID;
    $EUID = $UID;
    $EGID = $GID;
    # Drop privileges
    $UID  = $orig_uid;
    $GID  = $orig_gid;
    # Make sure privs are really gone
    ($EUID, $EGID) = @temp;
    die "Can't drop privileges"
      unless $UID == $EUID  && $GID eq $EGID;
    exec (@_) or die "can't exec $_[0]: $!";
  }
  return @ret;
}

sub keydb {
  my $self = shift; 
  my @ids = map { return unless /$self->{VKEYID}/; $_ } @_;
  my @moreopts = qw(--fingerprint --fingerprint --with-colons);
  my @opts = (split (/\s+/, $self->{FORCEDOPTS}), split (/\s+/, $self->{GPGOPTS}));
  my @keylist = backtick($self->{GPGBIN}, @opts, '--check-sigs', @moreopts, @ids); 
  my @seclist = backtick($self->{GPGBIN}, @opts, '--list-secret-keys', @moreopts, @ids); 
  @keylist = grep { /^...:.*:$/ } (@keylist, @seclist);
  $self->parsekeys (@keylist);
}

sub keyinfo {
  shift->keydb(@_);
}

sub parsekeys {
  my $self=shift; my @keylist = @_;
  my @keys; my ($i, $subkey, $subnum, $uidnum) = (-1);
  foreach (@keylist) {
    if (/^(pub|sec)/) {
      $uidnum=-1; $subnum=-1; $subkey=0;
      my ($type, $trust, $size, $algorithm, $id, $created, $expires, $u2, $ownertrust, $uid)
	= split (':');
      $keys[++$i] = { 
		     Type       =>    $type,
		     Calctrust  =>    $trust,
		     Ownertrust =>    $ownertrust,
		     Bits       =>    $size,
		     ID         =>    $id,
		     Created    =>    $created,
		     Expires    =>    $expires,
		     Algorithm  =>    $algorithm,
		     Use        =>    ''
		    };
      push (@{$keys[$i]->{UIDs}}, { UID => $uid }), $uidnum++ if $uid;
    }
    else {
      if (/^fpr:::::::::([^:]+):/) {
	my $fingerprint = $1; my $l = length $fingerprint;
	if ($l == 32) {
	  my @f = $fingerprint =~ /(..)/g;
	  $fingerprint = (join ' ', @f[0..7]) . '  ' . (join ' ', @f[8..15]);
	}
	elsif ($l == 40) {
	  my @f = $fingerprint =~ /(....)/g;
	  $fingerprint = (join ' ', @f[0..4]) . '  ' . (join ' ', @f[5..9]);
	}
	$subkey ?
	  $keys[$i]->{Subkeys}->[$subnum]->{Fingerprint} :
	  $keys[$i]->{Fingerprint} =  $fingerprint;
      }
      elsif (/^sub/) {
	$subnum++; $subkey      =     1;
	my ($type, $u1, $size, $algorithm, $id, $created, $expires)
	  = split (':');
	$keys[$i]->{Subkeys}->[$subnum] = 
	  {
	   Bits                 =>    $size,
	   ID                   =>    $id,
	   Created              =>    $created,
	   Expires              =>    $expires,
	   Algorithm            =>    $algorithm
	  };
      }
      elsif (/^sig/) {
	my ($sig, $u1, $u2, $u3, $id, $date, $u4, $u5, $u6, $uid)
	  = split (':');
	my ($pushto, $pushnum) = $subkey?('Subkeys',$subnum):('UIDs',$uidnum);
	push (@{$keys[$i]->{$pushto}->[$pushnum]->{Signatures}},
	      {	ID              =>    $id,
		Date            =>    $date,
		UID             =>    $uid
	      } );
      }
      elsif (/^uid:.*:([^:]+):$/) {
	$subkey = 0; $uidnum++;
	push (@{$keys[$i]->{UIDs}}, { UID => $1 });
      }
    }
  }
  return map {bless $_, 'Crypt::GPG::Key'} @keys;
}

sub keypass {
  my $self = shift; my ($key, $oldpass, $newpass) = @_;
  return unless $oldpass =~ /$self->{VPASSPHRASE}/ and $newpass =~ /$self->{VPASSPHRASE}/
    and $key->{Type} eq 'sec';
  my $opts = "$self->{FORCEDOPTS} $self->{GPGOPTS}";
  my $expect = Expect->spawn ("$self->{GPGBIN} $opts --edit-key $key->{ID}"); 
  $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, 'Command>'); sleep ($self->{DELAY}); print $expect ("passwd\r"); 
  $expect->expect (undef, 'phrase: '); sleep ($self->{DELAY}); print $expect ("$oldpass\r"); 
  $expect->expect (undef, 'please try again', 'phrase: '); 
  return undef if $expect->exp_match_number==1; sleep ($self->{DELAY}); print $expect ("$newpass\r"); 
  $expect->expect (undef, 'phrase: '); sleep ($self->{DELAY}); print $expect ("$newpass\r"); 
  $expect->expect (undef, 'Command>'); sleep ($self->{DELAY}); print $expect ("quit\r"); 
  $expect->expect (undef, 'changes?'); sleep ($self->{DELAY}); print $expect ("y\r"); 
  sleep ($self->{DELAY}); $expect->expect (undef);
  return 1;
}

sub keytrust {
  my $self = shift; my ($key, $trustlevel) = @_;
  return unless $trustlevel =~ /$self->{VTRUSTLEVEL}/;
  my $opts = "$self->{FORCEDOPTS} $self->{GPGOPTS}";
  my $expect = Expect->spawn ("$self->{GPGBIN} $opts --edit-key $key->{ID}"); 
  $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, 'Command>'); sleep ($self->{DELAY}); print $expect ("trust\r"); 
  $expect->expect (undef, 'decision? '); sleep ($self->{DELAY}); print $expect ("$trustlevel\r"); 
  $expect->expect (undef, 'Command>'); sleep ($self->{DELAY}); print $expect ("quit\r"); 
  sleep ($self->{DELAY}); $expect->expect (undef);
  return 1;  
}

sub delkey {
  my $self = shift; my $key = shift; 
  return unless $key->{ID} =~ /$self->{VKEYID}/;
  my $del = $key->{Type} eq 'sec'?'--delete-secret-and-public-key':'--delete-key';
  my $opts = "$self->{FORCEDOPTS} $self->{GPGOPTS}";
  return unless my $expect = Expect->spawn ("$self->{GPGBIN} $opts $del $key->{ID}"); 
  $expect->log_stdout($self->{DEBUG}); $expect->expect (undef, 'delete it first.', 'keyring?'); 
  return undef if ($expect->exp_match_number==1); 
  sleep ($self->{DELAY}); print $expect ("y\r"); 
  if ($key->{Type} eq 'sec') {
    $expect->expect (undef, 'really delete?'); sleep ($self->{DELAY}), print $expect ("y\r");
    $expect->expect (undef, 'keyring?'); sleep ($self->{DELAY}), print $expect ("y\r");
  }
  $expect->expect (undef);
  return 1;
}

sub disablekey {
  my $self = shift; my $key = shift;
  return unless $key->{ID} =~ /$self->{VKEYID}/;
  my $opts = "$self->{FORCEDOPTS} $self->{GPGOPTS}";
  return unless my $expect = Expect->spawn ("$self->{GPGBIN} $opts --edit-key $key->{ID}"); 
  $expect->log_stdout($self->{DEBUG}); $expect->expect (undef, 'been disabled', 'Command>'); 
  return undef if $expect->exp_match_number==1; sleep ($self->{DELAY}); print $expect ("disable\r"); 
  $expect->expect (undef, 'Command>'); sleep ($self->{DELAY}); print $expect ("quit\r"); 
  $expect->expect (undef, 'changes?'); sleep ($self->{DELAY}); print $expect ("y\r"); 
  sleep ($self->{DELAY}); $expect->expect (undef);
  return 1;
}

sub enablekey {
  my $self = shift; my $key = shift;
  return unless $key->{ID} =~ /$self->{VKEYID}/;
  my $opts = "$self->{FORCEDOPTS} $self->{GPGOPTS}";
  return unless my $expect = Expect->spawn ("$self->{GPGBIN} $opts --edit-key $key->{ID}"); 
  $expect->log_stdout($self->{DEBUG}); $expect->expect (undef, 'been disabled', 'Command>'); 
  return undef unless $expect->exp_match_number==1; sleep ($self->{DELAY}); print $expect ("enable\r"); 
  $expect->expect (undef, 'Command>'); sleep ($self->{DELAY}); print $expect ("quit\r"); 
  $expect->expect (undef, 'changes?'); sleep ($self->{DELAY}); print $expect ("y\r"); 
  sleep ($self->{DELAY}); $expect->expect (undef);
  return 1;
}

sub AUTOLOAD {
  my $self = shift; (my $auto = $AUTOLOAD) =~ s/.*:://;
  if ($auto =~ /^(passphrase|secretkey|armor|gpgbin|gpgopts|delay|
                  detach|encryptsafe|version|comment|debug)$/x) {
    $self->{"\U$auto"} = shift;
  }
  elsif ($auto eq 'DESTROY') {
  }
  else {
    croak "Could not AUTOLOAD method $auto.";
  }
}

'True Value';
__END__

=head1 NAME 

Crypt::GPG - An Object Oriented Interface to GnuPG.

=head1 VERSION

 $Revision: 1.25 $
 $Date: 2001/11/11 14:53:49 $

=head1 SYNOPSIS

  use Crypt::GPG;
  my $gpg = new Crypt::GPG;

  $gpg->gpgbin('/usr/bin/gpg');      # The GnuPG executable.
  $gpg->secretkey('0x2B59D29E');     # Set ID of default secret key.
  $gpg->passphrase('just testing');  # Set passphrase.

  # Sign a message:

  my $sign = $gpg->sign('testing again');

  # Encrypt a message:

  my @encrypted = $gpg->encrypt ('top secret', 'hash@netropolis.org');

  # Get message info:

  my @recipients = $gpg->msginfo($encrypted);

  # Decrypt / verify signature on a message, 

  my ($plaintext, $signature) = $gpg->verify($encrypted);

  # Key generation:

  $status = $gpg->keygen 
    ('Test', 'test@foo.com', 'ELG-E', 2048, 0, 'test passphrase');
  print while (<$status>); close $status;

  # Key database manipulation:

  $gpg->addkey(\@key);
  @keys = $gpg->keydb(@ids);

  # Key manipulation:

  $key = $keys[0];
 
  $gpg->delkey($key);
  $gpg->disablekey($key);
  $gpg->enablekey($key);
  $gpg->keypass($key, $oldpassphrase, $newpassphrase);
  $keystring = $gpg->export($key);

=head1 DESCRIPTION

The Crypt::GPG module provides near complete access to GnuPG
functionality through an object oriented interface. It provides
methods for encryption, decryption, signing, signature verification,
key generation, key export and import, and most other key management
functions. 

This module works almost identically to its cousin, Crypt::PGP5. The
two modules together provide a uniform interface to deal with both PGP
and GnuPG. Eventually, these modules will be folded into a single
module which will interface with GnuPG as well as all versions of PGP.

=head1 CONSTRUCTOR

=over 2

=item B<new()>

Creates and returns a new Crypt::GPG object.

=back

=head1 DATA METHODS

=over 2

=item B<gpgbin($path)>

Sets the B<GPGBIN> instance variable which gives the path to the GnuPG
binary.

=item B<gpgopts($opts)>

Sets the B<GPGOPTS> instance variable which may be used to pass
additional options to the GnuPG binary. For proper functioning of this
module, it is advisable to always include '--lock-multiple' in the
GPGOPTS string.

=item B<delay($seconds)>

Sets the B<DELAY> instance variable. This is the time (in seconds, or
fractions of seconds) to wait after receiving a prompt from the GnuPG
executable before starting to respond to it. I've noticed on some
machines that the executable hangs if it gets input too fast. The
delay is off by default.

=item B<secretkey($keyid)>

Sets the B<SECRETKEY> instance variable which may be a KeyID or a
username. This is the ID of the default key to use for signing.

=item B<passphrase($passphrase)>

Sets the B<PASSPHRASE> instance variable, required for signing and
decryption.

=item B<text($boolean)>

Sets the B<TEXT> instance variable. If set true, GnuPG will use
network-compatible line endings for proper cross-platform
compatibility and the plaintext will gain a newline at the end, if it
does not already have one.

=item B<signfirst($boolean)>

Sets the B<SIGNFIRST> instance variable. If set true 1, plaintext will
be signed before encryption. This is the way it should be done,
generally, unless you have good reason not to do it this way.

=item B<armor($boolean)>

Sets the B<ARMOR> instance variable, controlling the ASCII armoring of
output. The default is to use ascii-armoring. The module has not been
tested with this option turned off, and most likely will not work if
you switch this off.

=item B<detach($boolean)>

Sets the B<DETACH> instance variable. If set true, the sign method
will produce detached signature certificates, else it won't. The
default is to produce detached signatures.

=item B<encryptsafe($boolean)>

Sets the B<ENCRYPTSAFE> instance variable. If set true, encryption
will fail if trying to encrypt to a key which is not trusted. This is
the default. Turn this off if you want to encrypt to untrusted keys.

=item B<version($versionstring)>

Sets the B<VERSION> instance variable which can be used to change the
Version: string on the GnuPG output to whatever you like.

=item B<comment($commentstring)>

Sets the B<COMMENT> instance variable which can be used to change the
Comment: string on the GnuPG output to whatever you like.

=item B<debug($boolean)>

Sets the B<DEBUG> instance variable which causes the raw output of
Crypt::GPG's interaction with the GnuPG binary to be dumped to
STDOUT. By default, debugging is off.

=back

=head1 OBJECT METHODS

=over 2

=item B<sign(@message)>

Signs B<@message> with the secret key specified with B<secretkey()>
and returns the result as a string.

=item B<verify(\@message, [\@signature])>

This is just an alias for B<verify()>

=item B<verify(\@message, [\@signature])>

Decrypts and/or verifies the message in B<@message>, optionally using
the detached signature in B<@signature>, and returns a list whose
first element is plaintext message as a string. If the message was
signed, a Crypt::GPG::Signature object is returned as the second
element of the list.

=item B<msginfo(@ciphertext)>

Returns a list of the recipient key IDs that B<@ciphertext> is
encrypted to.

=item B<encrypt($plaintext, $keylist, [-sign] )>

Encrypts B<$plaintext> with the public keys of the recipients listed
in B<$keylist> and returns the result in a string, or B<undef> if
there was an error while processing. Returns undef if any of the keys
are not found.

Either $plaintext or $keylist may be specified as either an arrayref 
or a simple scalar.  If $plaintext is a an arrayref, it will be
join()ed without newlines. 

If the -sign option is provided, the message will be signed before
encryption. 

=item B<addkey(\@key, $pretend)>

Adds the keys given in B<@key> to the user's key ring and returns a
list of Crypt::GPG::Key objects corresponding to the keys that were
added. If B<$pretend> is true, it pretends to add the key and creates
the key object, but doesn't actually perform the key addition.

=item B<export($key)>

Exports the key specified by the Crypt::GPG::Key object B<$key> and
returns the result as a string.

=item B<keygen($name, $email, $keytype, $keysize, $expire, $passphrase)>

Creates a new keypair with the parameters specified. The only
supported B<$keytype> currently is 'ELG-E'. B<$keysize> can be any of
768, 1024, 2048, 3072 or 4096. Returns undef if there was an error,
otherwise returns a filehandle that reports the progress of the key
generation process similar to the way GnuPG does. The key generation
is not complete till you read an EOF from the returned filehandle.

=item B<keydb(@keyids)>

Returns an array of Crypt::GPG::Key objects corresponding to the Key
IDs listed in B<@keyids>. This method used to be called B<keyinfo> and
that is still an alias to this method.

=item B<parsekeys(@keylist)>

Parses a raw GnuPG formatted key listing in B<@keylist> and returns an
array of Crypt::GPG::Key objects.

=item B<keypass($key, $oldpass, $newpass)>

Change the passphrase for a key. Returns true if the passphrase change
succeeded, false if not, or undef if there was an error.

=item B<delkey($keyid)>

Deletes the key specified by the Crypt::GPG::Key object B<$key> from
the user's key ring. Returns undef if there was an error, or 1 if the
key was successfully deleted.

=item B<disablekey($keyid)>

Disables the key specified by the Crypt::GPG::Key object B<$key>.

=item B<enablekey($keyid)>

Enables the key specified by the Crypt::GPG::Key object B<$key>.

=back

=head1 BUGS

=over 2

=item * 

Error checking needs work. 

=item * 

Some key manipulation functions are missing. 

=item * 

The method call interface is subject to change in future versions.
Key manipulation methods will be encapsulated into the Crypt::GPG::Key
class.

=item * 

The current implementation will probably eat up all your RAM if you
try to operate on huge messages. In future versions, this will be
addressed by reading from and returning filehandles, rather than using
in-core data.

=item * 

Methods may break if you don't use ASCII armoring.

=back

=head1 AUTHOR

Crypt::GPG is Copyright (c) 2000-2001 Ashish Gulhati
<hash@netropolis.org>. All Rights Reserved.

=head1 ACKNOWLEDGEMENTS

Thanks to Barkha for inspiration and lots of laughs, and to the GnuPG
team.

=head1 LICENSE

This code is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

