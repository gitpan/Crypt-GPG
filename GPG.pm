# -*-cperl-*-
#
# Crypt::GPG - An Object Oriented Interface to GnuPG.
# Copyright (c) 2000-2002 Ashish Gulhati <hash@netropolis.org>
#
# All rights reserved. This code is free software; you can
# redistribute it and/or modify it under the same terms as Perl
# itself.
#
# $Id: GPG.pm,v 1.42 2002/12/11 03:33:19 cvs Exp $

package Crypt::GPG;

use Carp;
use Fcntl;
use Expect;
use strict;
use File::Path;
use Date::Parse;
use Time::HiRes qw( sleep );
use File::Temp qw( tempfile tempdir );
use vars qw( $VERSION $AUTOLOAD );

File::Temp->safe_level( File::Temp::HIGH );
( $VERSION ) = '$Revision: 1.42 $' =~ /\s+([\d\.]+)/;

sub new {
  bless { GPGBIN         =>   'gpg',
	  FORCEDOPTS     =>   '--no-secmem-warning',
	  GPGOPTS        =>   '--lock-multiple --compress-algo 1 ' .
	                      '--cipher-algo cast5 --force-v3-sigs',
	  VERSION        =>   $VERSION,
	  DELAY          =>   0.1,
	  PASSPHRASE     =>   '',
	  COMMENT        =>   "Crypt::GPG v$VERSION",
	  ARMOR          =>   1,
	  DETACH         =>   1,
	  ENCRYPTSAFE    =>   1,
	  TEXT           =>   1,
	  SECRETKEY      =>   '',
	  DEBUG          =>   0,
	  TMPFILES       =>   'fileXXXXXX',
	  TMPDIRS        =>   'dirXXXXXX',
	  TMPDIR         =>   '/tmp',
	  TMPSUFFIX      =>   '.dat',
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
  my $self = shift; 

  return unless $self->{SECRETKEY} =~ /$self->{VKEYID}/ 
    and $self->{PASSPHRASE} =~ /$self->{VPASSPHRASE}/;

  my $detach    = '-b' if $self->{DETACH}; 
  my $armor     = '-a' if $self->{ARMOR}; 
  my @extras    = ($detach, $armor);

  my @secretkey = ('--default-key', $self->{SECRETKEY});

  my ($tmpfh, $tmpnam) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);

  my $message = join ('', @_); 
  $message .= "\n" unless $message =~ /\n$/s;
  print $tmpfh $message; close $tmpfh; 

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  push (@opts, ('--comment', $self->{COMMENT})) if $self->{COMMENT};
  my $expect = Expect->spawn 
    ($self->{GPGBIN}, @opts, '-o-', '--sign', @extras, 
     @secretkey, $tmpnam);
  $expect->log_stdout($self->{DEBUG});

  $expect->expect (undef, '-re', '-----BEGIN', 'passphrase:', 'signing failed');
  if ($expect->exp_match_number == 2) {
    $self->doze(); print $expect "$self->{PASSPHRASE}\r";
    $expect->expect (undef, '-re', '-----BEGIN', 'passphrase:');
    if ($expect->exp_match_number == 2) {
      $self->doze(); print $expect "$self->{PASSPHRASE}\r";    
      $expect->expect (undef, 'passphrase:'); $self->doze(); 
      print $expect "$self->{PASSPHRASE}\r";    
      $expect->expect (undef);
      unlink $tmpnam; 
      return;
    }
  }
  elsif ($expect->exp_match_number == 3) {
    unlink $tmpnam; $expect->close;
    return;
  }
  $expect->expect (undef); 
  my $info = $expect->exp_match() . $expect->exp_before(); 
  unlink $tmpnam;
  return $info;
}

sub decrypt { shift->verify(@_); }

sub verify {
  my $self = shift; 
  my ($tmpfh3, $tmpnam3);

  return unless $self->{PASSPHRASE} =~ /$self->{VPASSPHRASE}/;

  my ($tmpfh, $tmpnam) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);
  my ($tmpfh2, $tmpnam2) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);

  my $ciphertext = ref($_[0]) ? join '', @{$_[0]} : $_[0];
  $ciphertext .= "\n" unless $ciphertext =~ /\n$/s;
  print $tmpfh $ciphertext; close $tmpfh;

  if ($_[1]) {
    my $signature = ref($_[1]) ? join '', @{$_[1]} : $_[1];
    ($tmpfh3, $tmpnam3) = 
      tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
		SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);
    print $tmpfh3 $signature; close $tmpfh3;
  }

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  push (@opts, ('--comment', $self->{COMMENT})) if $self->{COMMENT};
  my $expect = Expect->spawn ($self->{GPGBIN}, @opts, '--yes', 
			      '--decrypt', '-o', $tmpnam2, $tmpnam);
  $expect->log_stdout($self->{DEBUG});

  $expect->expect 
    (undef, '-re', '^gpg:', '-re', 'passphrase:\s*', 
     '-re', 'data file:');

  if ($expect->exp_match_number==3) {
    $self->doze(); print $expect "$tmpnam3\r";
    $expect->expect 
      (undef, '-re', 'gpg:', '-re', 'passphrase:\s*');
  }

  if ($expect->exp_match_number==2) {
    $self->doze(); print $expect "$self->{PASSPHRASE}\r";


    #! Suggested mod (yu\x40math.duke.edu) - change below:
    $expect->expect 
      (undef, '-re', 'gpg: encrypted', '-re', 'passphrase:\s*');
    if ($expect->exp_match_number()==2) {
      unlink $tmpnam3 if $tmpnam3;
      close $tmpfh2; close $expect; 
      unlink ($tmpnam, $tmpnam2);
      return;
    }
    #! to:
    #!# try again in case the message was encrypted for multiple recipients
#!    $expect->expect(undef,
#!		    [ qr/passphrase:\s*/i, sub { my $slf = shift;
#!						 $self->doze(); $slf->send("$self->{PASSPHRASE}\r");
#!						 exp_continue; }],
#!		    '-re', 'gpg: encrypted');

  }

  $self->doze(); $expect->expect (undef); 
  unlink $tmpnam; unlink $tmpnam3 if $_[1];

  my $info = $expect->exp_match() . $expect->exp_before(); 
  $info =~ s/\r//sg;
  my $trusted = ($info !~ /WARNING: This key is not certified/s);
  my $unknown = ($info =~ /Can't check signature: public key not found/s);
  my $plaintext = join ('',<$tmpfh2>) || ''; 
  close $tmpfh2; unlink ($tmpnam2);

  return ($plaintext) 
    unless $info =~ /.*Signature\ made\ ((?:\S+\s+){6,7})
                     using\ \S+\ key\ ID\ (\S+)
	             \s*gpg:\ (Good|BAD)\ signature\ from/sx;

  my $signature = {'Validity' => $3, 'KeyID' => $2, 
		   'Time' => $1, 'Trusted' => $trusted};
  $signature->{Time} = str2time ($signature->{Time}); 
  bless $signature, 'Crypt::GPG::Signature';
  return ($plaintext, $signature);
}

sub msginfo {
  my $self = shift; 
  my @return;

  my ($tmpfh, $tmpnam) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);
  print $tmpfh join '',@{$_[0]}; close $tmpfh; 

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  my $expect = Expect->spawn 
    ($self->{GPGBIN}, @opts, '--batch', $tmpnam); 
  $expect->log_stdout($self->{DEBUG});

  $self->doze(); $expect->expect (undef); 
  my $info = $expect->exp_before();
  $info =~ s/key, ID (.{8})/{push @return, $1}/sge; 
  unlink $tmpnam;
  return @return;
}

sub encrypt {
  my $self = shift; 
  my ($message, $rcpts) = @_;
  my $info;

  my $sign = $_[2] && $_[2] eq '-sign' ? '--sign' : '';
  my $armor = $self->{ARMOR} ? '-a' : '';

  if ($sign) {
    return unless $self->{SECRETKEY} =~ /$self->{VKEYID}/ 
      and $self->{PASSPHRASE} =~ /$self->{VPASSPHRASE}/;
  }

  my @rcpts;
  if (ref($rcpts) eq 'ARRAY') {
    @rcpts = map { 
      return unless /$self->{VRCPT}/; 
      ('-r', $_) } @$rcpts;
  }
  else {
    return unless $rcpts =~ /$self->{VRCPT}/;
    @rcpts = ('-r', $rcpts);
  }

  my ($tmpfh, $tmpnam) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);

  $message = join ('', @$message) if ref($message) eq 'ARRAY'; 
  print $tmpfh $message; close $tmpfh;

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  push (@opts, '--default-key', $self->{SECRETKEY}) if $sign;
  push (@opts, $sign) if $sign; push (@opts, $armor) if $armor;
  push (@opts, ('--comment', $self->{COMMENT})) if $self->{COMMENT};
  my $expect = Expect->spawn ($self->{GPGBIN}, @opts, '-o-', 
			      @rcpts, '--encrypt', $tmpnam);
  $expect->log_stdout($self->{DEBUG});

  my ($pos, $err, $matched, $before, $after);
  
  if ($sign) {
    ($pos, $err, $matched, $before, $after) =    
      $expect->expect(undef, '-re', '-----BEGIN PGP', 
		      'Use this key anyway?', 'key not found', 
		      'phrase:');
    return if $err;
    if ($pos==4) {
      $self->doze(); print $expect "$self->{PASSPHRASE}\r";
      ($pos, $err, $matched, $before, $after) = 
	$expect->expect(undef, '-re', '-----BEGIN PGP', 
			'Use this key anyway?', 
			'key not found', 'phrase:');
      return if ($pos==4);
      return if $err;
    }
  }
  
  while (1) {
    unless ($pos) {
      ($pos, $err, $matched, $before, $after) = $expect->expect 
	(undef, '-re', '-----BEGIN PGP', 
	 'Use this key anyway?', 'key not found');
    }
    return if $err;
    if ($pos==2) {
      $self->doze();
      if ($self->{ENCRYPTSAFE}) {
	print $expect "n\n"; 
	$expect->expect (undef); 
	unlink $tmpnam;
	return;
      }
      else {
	print $expect "y\n";
      }	
    }
    elsif ($pos==3) {
      $expect->expect (undef); 
      unlink $tmpnam;
      return;
    }
    else {
      $info = $matched;
      last;
    }
  }
  $expect->expect (undef);
  $info .= $expect->exp_before(); 
  $info =~ s/.*\n(-----BEGIN PGP)/$1/s;
  unlink $tmpnam;
  return $info;
}

sub addkey {
  my $self = shift;
  my ($key, $pretend, @keyids) = @_;

  $key = join ('', @$key) if ref($key) eq 'ARRAY'; 
  return if grep { $_ !~ /^[a-f0-9]+$/i } @keyids;

  my $tmpdir = tempdir( $self->{TMPDIRS}, 
		     DIR => $self->{TMPDIR}, CLEANUP => 1);
  my ($tmpfh, $tmpnam) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);
  print $tmpfh $key;

  my @pret1 = ('--options', '/dev/null', '--homedir', $tmpdir);
  my @pret2 = ('--keyring', "$tmpdir/pubring.gpg", 
	       '--secret-keyring', "$tmpdir/secring.gpg");
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  my @listopts = qw(--fingerprint --fingerprint --with-colons);

  my @info = backtick($self->{GPGBIN}, @opts, @pret1, '-v', 
		      '--import', $tmpnam);
  my @keylist = backtick($self->{GPGBIN}, @opts, @pret1,
			 '--check-sigs', @listopts, @keyids); 
  my @seclist = backtick($self->{GPGBIN}, @opts, @pret1,
			 '--list-secret-keys', @listopts);

  my @seckeys = grep { my $id = $_->{ID}; 
		       (grep { $id eq $_ } @keyids) ? $_ : '' } 
    $self->parsekeys(@seclist);
  my @ret = ($self->parsekeys(@keylist), @seckeys);
  
  if ($pretend) {
    @keylist = backtick($self->{GPGBIN}, @opts, @pret2, 
			'--check-sigs', @listopts); 
    my @realkeylist = grep { my $id = $_->{ID} if $_; 
			     $id and grep { $id eq $_->{ID} } @ret } 
      map { ($_->{Keyring} eq "$tmpdir/secring.gpg" 
	     or $_->{Keyring} eq "$tmpdir/pubring.gpg") ? $_ : 0 } 
	$self->parsekeys(@keylist);
    @ret = (@realkeylist, @seckeys);
  }
  else {
    if (@keyids) {
      my @info = backtick($self->{GPGBIN}, @opts, @pret1, 
			  "--export", '-a', @keyids);
      print $tmpfh (join '', @info); close $tmpfh;
    }
    my @info = backtick($self->{GPGBIN}, @opts, '-v', 
			'--import', $tmpnam);
  }
  rmtree($tmpdir, 0, 1);
  unlink($tmpnam);
  return @ret;
}

sub export {
  my $self = shift; 
  my $key = shift; 
  my $id = $key->{ID}; 
  return unless $id =~ /$self->{VKEYID}/;

  my $armor = $self->{ARMOR} ? '-a' : '';
  my $secret = $key->{Type} eq 'sec' ? '-secret-keys' : '';
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  push (@opts, ('--comment', $self->{COMMENT})) if $self->{COMMENT};

  join('', backtick($self->{GPGBIN}, @opts, 
		    "--export$secret", $armor, $id));
}

sub keygen {
  my $self = shift; 
  my ($name, $email, $keytype, $keysize, $expire, $pass) = @_;

  return unless $keysize =~ /$self->{VKEYSZ}/ 
    and $keysize > 767 and $keysize < 4097
      and $pass =~ /$self->{VPASSPHRASE}/
	and $keytype =~ /$self->{VKEYTYPE}/ 
	  and $expire =~ /$self->{VEXPIRE}/ 
	    and $email =~ /$self->{VEMAIL}/
	      and $name =~ /$self->{VNAME}/ 
		and length ($name) > 4;

  my $bigkey = ($keysize > 1536);   
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  for (0..1) { 
    backtick ($self->{GPGBIN}, @opts, '--no-tty', '--gen-random', 0, 1); 
  }

  my $pid = open(GPG, "-|");
  return undef unless (defined $pid);

  if ($pid) {
    $SIG{CHLD} = 'IGNORE';
    return \*GPG;
  }
  else {
    my $expect = Expect->spawn ($self->{GPGBIN}, @opts, '--gen-key'); 
    $expect->log_stdout(0);
    $expect->expect (undef, 'selection?'); $self->doze(); 
    print $expect ( "1\r"); print ".\n";
    $expect->expect (undef, 'do you want?'); $self->doze(); 
    print $expect ("$keysize\r"); print ".\n";
    $expect->expect (undef, 'keysize?'), $self->doze(), 
      print $expect ("y\r"), print ".\n" if $bigkey;
    $expect->expect (undef, 'valid for?'); $self->doze(); 
    print $expect ("$expire\r"); print ".\n";
    $expect->expect (undef, '(y/n)?'); $self->doze(); 
    print $expect ("y\r"); print ".\n";
    $expect->expect (undef, 'name:'); $self->doze(); 
    print $expect ("$name\r"); print ".\n"; 
    $expect->expect (undef, 'address:'); $self->doze(); 
    print $expect ("$email\r"); print ".\n";
    $expect->expect (undef, 'Comment:'); $self->doze(); 
    print $expect ("\r"); print ".\n";
    $expect->expect (undef, 'uit?'); $self->doze(); 
    print $expect ("o\r"); print ".\n";
    $expect->expect (undef, 'phrase: '); $self->doze(); 
    print $expect ("$pass\r"); print ".\n";
    $expect->expect (undef, 'phrase: '); $self->doze(); 
    print $expect ("$pass\r"); print ".\n";
    $expect->expect (undef, '-re', '([\+\.\>\<\^]|created and signed)');
    my $x = $expect->exp_match(); 
    while ($x !~ /created and signed/) {
      print "$x\n";
      my $t = $expect->expect 
	(1, '-re', '([\+\.\>\<\^]|created and signed)');
      $x = $expect->exp_match();
    }	
    print "|\n";
    $self->doze(); $expect->expect (undef, 'nothing.');
    exit();
  }
}

sub keydb {
  my $self = shift; 
  my @ids = map { return unless /$self->{VKEYID}/; $_ } @_;
  my @moreopts = qw(--fingerprint --fingerprint --with-colons);
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  my @keylist = backtick($self->{GPGBIN}, @opts, 
			 '--check-sigs', @moreopts, @ids); 
  $self->doze();
  my @seclist = backtick($self->{GPGBIN}, @opts, 
			 '--list-secret-keys', @moreopts, @ids); 
  @keylist = grep { /^...:.*:$/ } (@keylist, @seclist);
  $self->parsekeys (@keylist);
}

sub keyinfo {
  shift->keydb(@_);
}

sub parsekeys {
  my $self=shift; my @keylist = @_;
  my @keys; my ($i, $subkey, $subnum, $uidnum) = (-1);
  my $keyring = '';
  foreach (@keylist) {
    next if /^\-/;
    if (/^\//) {
      $keyring = $_; chomp $keyring;
      next;
    }
    if (/^(pub|sec)/) {
      $uidnum=-1; $subnum=-1; $subkey=0;
      my ($type, $trust, $size, $algorithm, $id, $created, 
	  $expires, $u2, $ownertrust, $uid) = split (':');
      $keys[++$i] = { 
		     Keyring    =>    $keyring,
		     Type       =>    $type,
		     Ownertrust =>    $ownertrust,
		     Bits       =>    $size,
		     ID         =>    $id,
		     Created    =>    $created,
		     Expires    =>    $expires,
		     Algorithm  =>    $algorithm,
		     Use        =>    ''
		    };
      push (@{$keys[$i]->{UIDs}}, { 'UID' => $uid, 'Calctrust' => $trust }), 
	$uidnum++ if $uid;
    }
    else {
      if (/^fpr:::::::::([^:]+):/) {
	my $fingerprint = $1; my $l = length $fingerprint;
	if ($l == 32) {
	  my @f = $fingerprint =~ /(..)/g;
	  $fingerprint = (join ' ', @f[0..7]) . '  ' . 
	    (join ' ', @f[8..15]);
	}
	elsif ($l == 40) {
	  my @f = $fingerprint =~ /(....)/g;
	  $fingerprint = (join ' ', @f[0..4]) . '  ' . 
	    (join ' ', @f[5..9]);
	}
	$subkey ?
	  $keys[$i]->{Subkeys}->[$subnum]->{Fingerprint} :
	  $keys[$i]->{Fingerprint} =  $fingerprint;
      }
      elsif (/^sub/) {
	$subnum++; $subkey      =     1;
	my ($type, $u1, $size, $algorithm, $id, 
	    $created, $expires) = split (':');
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
	my ($sig, $valid, $u2, $u3, $id, $date, 
	    $u4, $u5, $u6, $uid) = split (':');
	my ($pushto, $pushnum) = $subkey ? 
	  ('Subkeys',$subnum) : ('UIDs',$uidnum);
	push (@{$keys[$i]->{$pushto}->[$pushnum]->{Signatures}},
	      {	ID              =>    $id,
		Date            =>    $date,
		UID             =>    $uid,
		Valid           =>    $valid
	      } );
      }
      elsif (/^uid:(.?):.*:([^:]+):$/) {
	$subkey = 0; $uidnum++;
	push (@{$keys[$i]->{UIDs}}, { UID => $2, Calctrust => $1 });
      }
    }
  }
  return map {bless $_, 'Crypt::GPG::Key'} @keys;
}

sub keypass {
  my $self = shift; 

  my ($key, $oldpass, $newpass) = @_;
  return unless $oldpass =~ /$self->{VPASSPHRASE}/ 
    and $newpass =~ /$self->{VPASSPHRASE}/
      and $key->{Type} eq 'sec';

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  my $expect = Expect->spawn ($self->{GPGBIN}, @opts, 
			      '--edit-key', $key->{ID}); 
  $expect->log_stdout($self->{DEBUG});

  $expect->expect (undef, 'Command>'); $self->doze(); 
  print $expect ("passwd\r"); 
  $expect->expect (undef, 'This key is not protected.', 'phrase: '); 
  if ($expect->exp_match_number == 1) {
    $expect->close, return if $oldpass;
  }
  else {
    $self->doze(); print $expect ("$oldpass\r"); 
    $expect->expect (undef, 'please try again', 'phrase: '); 
    if ($expect->exp_match_number == 1) {

      #! Suggested mod (yu\x40math.duke.edu) - Change below:
      $self->doze(); print $expect "$self->{PASSPHRASE}\r";
      $expect->expect (undef, 'passphrase:');
      $self->doze(); print $expect "$self->{PASSPHRASE}\r";    
      $expect->expect (undef, 'Command>'); 
      $self->doze(); print $expect ("quit\r");
      $expect->expect (undef);
      return;
      #! To:
      #!       $expect->close; return;
    }
  }
  $self->doze(); print $expect ("$newpass\r"); 
  $expect->expect (undef, 'Repeat passphrase: '); 
  $self->doze(); print $expect ("$newpass\r"); 
  $expect->expect (undef, 'really want to do this?', 'Command>'); 
  if ($expect->exp_match_number == 1) {
    $self->doze(); print $expect "y\r";
    $expect->expect (undef, 'Command>'); 
  }
  $self->doze(); print $expect ("quit\r"); 
  $expect->expect (undef, 'changes?'); $self->doze(); 
  print $expect ("y\r"); 
  $self->doze(); $expect->expect (undef);
  return 1;
}

sub keytrust {
  my $self = shift; 
  my ($key, $trustlevel) = @_;
  return unless $trustlevel =~ /$self->{VTRUSTLEVEL}/;

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  my $expect = Expect->spawn ($self->{GPGBIN}, @opts, 
			      '--edit-key', $key->{ID}); 
  $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, 'Command>'); $self->doze(); 
  print $expect ("trust\r"); 
  $expect->expect (undef, 'decision? '); $self->doze(); 
  print $expect ("$trustlevel\r"); 
  $expect->expect (undef, 'Command>'); $self->doze(); 
  print $expect ("quit\r"); 
  $self->doze(); $expect->expect (undef);
  return 1;  
}

sub certify {
  my $self = shift; 
  my ($key, $local, @uids) = @_; 
  my $ret = 1;

  return unless $self->{SECRETKEY} =~ /$self->{VKEYID}/ 
    and $self->{PASSPHRASE} =~ /$self->{VPASSPHRASE}/;
  
  return unless @uids and !grep { $_ =~ /\D/; } @uids; 
  my $i = 0;

  ($key) = $self->keydb($key);
  my $signingkey = ($self->keydb($self->{SECRETKEY}))[0]->{ID};

  #! Check if already signed. Buggy! 
  #! Fix this and remove postemptive check below
  return 1 unless grep { !grep { $signingkey eq $_->{ID} } 
			   @{$_->{Signatures}} } 
    (@{$key->{UIDs}})[@uids];

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  push (@opts, '--default-key', $self->{SECRETKEY});
  my $expect = Expect->spawn ($self->{GPGBIN}, @opts, 
			      '--edit-key', $key->{ID}); 
  $expect->log_stdout($self->{DEBUG});

  for (@uids) {
    my $uid = $_+1;
    $expect->expect (undef, 'Command>'); $self->doze(); 

    # Hack to make UID numbers correspond correctly.

    my $info = $expect->exp_before();
    $info =~ /\((\d+)\)\./; my $primary = $1;
    unless ($primary == 1) {
      if ($uid == 1) {
	$uid = $primary;
      }
      elsif ($uid <= $primary) {
	$uid--;
      }
    }

    print $expect ("uid $uid\r"); 
  }
  $expect->expect (undef, 'Command>'); $self->doze(); 
  print $expect ($local ? "lsign\r" : "sign\r"); 
  #! Postemptive check. Fix pre-emptive check & remove this.
  my $hack = 1;
  $expect->expect (undef, 'sign?', 'Already signed', 'Unable to sign.'); $self->doze(); 
  if ($expect->exp_match_number == 1) {
    print $expect ("y\r"); 
    $expect->expect (undef, 'phrase:'); $self->doze(); 
    print $expect "$self->{PASSPHRASE}\r"; 
    $expect->expect (undef, 'Command>', 'phrase:');
    if ($expect->exp_match_number == 2) {
      $self->doze(); print $expect "$self->{PASSPHRASE}\r";
      $expect->expect (undef, 'passphrase:');
      $self->doze(); print $expect "$self->{PASSPHRASE}\r";    
      $expect->expect (undef, 'Command>');
      $ret = 0;
    }
  }
  else {
    $expect->expect (undef, 'Command>');
    $ret = 1; $hack = 0;
  }
  $self->doze(); print $expect ("quit\r"); 
  if ($ret and $hack) {
    $expect->expect (undef, 'changes?'); $self->doze(); 
    print $expect ("y\r"); 
  }
  $self->doze(); $expect->expect (undef);
  $ret;  
}

sub delkey {
  my $self = shift; 
  my $key = shift; 
  return unless $key->{ID} =~ /$self->{VKEYID}/;

  my $del = $key->{Type} eq 'sec' ?
    '--delete-secret-and-public-key':'--delete-key';
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));

  return unless my $expect = Expect->spawn ($self->{GPGBIN}, @opts, 
					    $del, $key->{ID}); 
  $expect->log_stdout($self->{DEBUG}); 
  $expect->expect (undef, 'delete it first.', 'keyring?'); 
  return undef if ($expect->exp_match_number==1); 
  $self->doze(); print $expect ("y\r"); 
  if ($key->{Type} eq 'sec') {
    $expect->expect (undef, 'really delete?'); $self->doze(), 
      print $expect ("y\r");
    $expect->expect (undef, 'keyring?'); $self->doze(), 
      print $expect ("y\r");
  }
  $expect->expect (undef);
  return 1;
}

sub disablekey {
  my $self = shift; 
  my $key = shift;
  return unless $key->{ID} =~ /$self->{VKEYID}/;

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  return unless my $expect = Expect->spawn ($self->{GPGBIN}, @opts, 
					    '--edit-key', $key->{ID}); 
  $expect->log_stdout($self->{DEBUG}); 

  $expect->expect (undef, 'been disabled', 'Command>'); 
  return undef if $expect->exp_match_number==1; $self->doze(); 
  print $expect ("disable\r"); 
  $expect->expect (undef, 'Command>'); $self->doze(); 
  print $expect ("quit\r"); 
  $expect->expect (undef, 'changes?'); $self->doze(); 
  print $expect ("y\r"); 
  $self->doze(); $expect->expect (undef);
  return 1;
}

sub enablekey {
  my $self = shift; 
  my $key = shift;
  return unless $key->{ID} =~ /$self->{VKEYID}/;

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  return unless my $expect = Expect->spawn ($self->{GPGBIN}, @opts, 
					    '--edit-key', $key->{ID}); 
  $expect->log_stdout($self->{DEBUG}); 

  $expect->expect (undef, 'been disabled', 'Command>'); 
  return undef unless $expect->exp_match_number==1; $self->doze(); 
  print $expect ("enable\r"); 
  $expect->expect (undef, 'Command>'); $self->doze(); 
  print $expect ("quit\r"); 
  $expect->expect (undef, 'changes?'); $self->doze(); 
  print $expect ("y\r"); 
  $self->doze(); $expect->expect (undef);
  return 1;
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

sub doze {
  sleep shift->{DELAY};
}

sub AUTOLOAD {
  my $self = shift; (my $auto = $AUTOLOAD) =~ s/.*:://;
  if ($auto =~ /^(passphrase|secretkey|armor|gpgbin|gpgopts|delay|
                  detach|encryptsafe|version|comment|debug)$/x) {
    return $self->{"\U$auto"} unless defined $_[0];
    $self->{"\U$auto"} = shift;
  }
  elsif ($auto eq 'DESTROY') {
  }
  else {
    croak "Could not AUTOLOAD method $auto.";
  }
}

package Crypt::GPG::Signature;
use vars qw( $AUTOLOAD );
use Carp;

sub AUTOLOAD {
  my $self = shift; (my $auto = $AUTOLOAD) =~ s/.*:://;
  if ($auto =~ /^(validity|keyid|time|trusted)$/) {
    return $self->{"KeyID"} if ( $auto eq "keyid" );
    return $self->{"\u$auto"};
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

 $Revision: 1.42 $
 $Date: 2002/12/11 03:33:19 $

=head1 SYNOPSIS

  use Crypt::GPG;
  my $gpg = new Crypt::GPG;

  $gpg->gpgbin('/usr/bin/gpg');      # The GnuPG executable.
  $gpg->secretkey('0x2B59D29E');     # Set ID of default secret key.
  $gpg->passphrase('just testing');  # Set passphrase.

  # Sign a message:

  my $sign = $gpg->sign('testing again');

  # Encrypt a message:

  my @encrypted = $gpg->encrypt ('top secret', 'test@bar.com');

  # Get message info:

  my @recipients = $gpg->msginfo($encrypted);

  # Decrypt / verify signature on a message, 

  my ($plaintext, $signature) = $gpg->verify($encrypted);

  # Key generation:

  $status = $gpg->keygen 
    ('Test', 'test@foo.com', 'ELG-E', 2048, 0, 'test passphrase');
  print while (<$status>); close $status;

  # Key database manipulation:

  $gpg->addkey($key, @ids);
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

=item B<decrypt(\@message, [\@signature])>

This is just an alias for B<verify()>

=item B<verify(\@message, [\@signature])>

Decrypts and/or verifies the message in B<@message>, optionally using
the detached signature in B<@signature>, and returns a list whose
first element is plaintext message as a string. If the message was
signed, a Crypt::GPG::Signature object is returned as the second
element of the list.

The Crypt::GPG::Signature object can be queried with the following
methods:

   $sig->validity();    # 'Good', 'BAD', or 'Unknown'
   $sig->keyid();       # ID of signing key
   $sig->time();        # Time the signature was made
   $sig->trusted();     # True or false depending on whether 
                          the signing key is trusted

=item B<msginfo(@ciphertext)>

Returns a list of the recipient key IDs that B<@ciphertext> is
encrypted to.

=item B<encrypt($plaintext, $keylist, [-sign] )>

Encrypts B<$plaintext> with the public keys of the recipients listed
in B<$keylist> and returns the result in a string, or B<undef> if
there was an error while processing. Returns undef if any of the keys
are not found.

Either $plaintext or $keylist may be specified as either an arrayref
or a simple scalar.  

If $plaintext is a an arrayref, it will be join()ed without
newlines. 

If you want to encrypt to multiple recipients, you must use the
arrayref version of $keylist. A scalar $keylist works for only a
single key ID.

If the -sign option is provided, the message will be signed before
encryption. The secret key and passphrase must be set for signing to
work. They can be set with the secretkey() and passphrase() methods.

=item B<addkey($key, $pretend, @keyids)>

Adds the keys given in B<$key> to the user's key ring and returns a
list of Crypt::GPG::Key objects corresponding to the keys that were
added. $key may be a string or an array reference. 

If B<$pretend> is true, it pretends to add the key and creates the key
object, but doesn't actually perform the key addition.

Optionally, a list of key IDs may be specified. If a list of key IDs
is specified, only keys that match those IDs will be imported. The
rest will be ignored.

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

=item B<certify($keyid, $local, @uids)>

Certifies to the authenticity of UIDs of the key with ID $keyid. If
$local is true, the certification will be non-exportable. The @uids
parameter should contain the list of UIDs to certify (the first UID of
a key is 0).

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

=head1 Crypt::GPG::Signature

=over 2

  Documentation coming soon.

=back

=head1 Crypt::GPG::Key

=over 2

  Documentation coming soon.

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

=head1 CHANGELOG

=over 2

$Log: GPG.pm,v $
Revision 1.42  2002/12/11 03:33:19  cvs

 - Fixed bug in certify() when trying to certify revoked a key.

 - Applied dharris\x40drh.net's patch to allow for varying date formats
   between gpg versions, and fix time parsing and the
   Crypt::GPG::Signature autoloaded accessor functions.

Revision 1.40  2002/09/23 23:01:53  cvs

 - Fixed a bug in keypass()

 - Documentation fixes.

Revision 1.37  2002/09/21 02:37:49  cvs

 - Fixed signing option in encrypt.

Revision 1.36  2002/09/21 00:03:29  cvs

 - Added many tests and fixed a bunch of bugs.

Revision 1.34  2002/09/20 19:07:11  cvs

 - Extensively modified formatting to make the code easier to
   read. All lines are now < 80 chars.

 - Removed all instances of invoking a shell.

 - Misc. other stuff.

Revision 1.31  2002/09/20 16:38:45  cvs

 - Cleaned up export and addkey. Fixed(?) addkey clobbering trustdb
   problem (thanks to jrray\x40spacemeat.com for the patch). Added
   support for signature verification on addkey pretend.

 - No calls to POSIX::tmpnam remain (thanks to radek\x40karnet.pl and
   jrray\x40spacemeat.com for suggesting File::Temp).

Revision 1.30  2002/09/20 15:25:47  cvs

 - Fixed up tempfile handling and eliminated calls to the shell in
   encrypt(), sign() and msginfo(). Passing all currently defined
   tests. 

 - Hopefully also fixed signing during encryption and verification of
   detached signatures. Not tested this yet.

Revision 1.29  2002/09/20 11:19:02  cvs

 - Removed hack to Version: string. Only the Comment: string in GPG
   output is now modified by Crypt::GPG. (Thanks to
   eisen\x40schlund.de for pointing out the bug here)

 - Removed code that incorrectly replaced 'PGP MESSAGE' with 'PGP
   SIGNATURE' on detached signatures. (Thanks to ddcc\x40mit.edu for
   pointing this out).

 - Fixed up addkey() to properly handle pretend mode and to
   selectively import only requested key IDs from a key block.

 - parsekeys() now also figures out which keyring a key belongs to.

 - Added certify() method, to enable certifying keys.

 - Added Crypt::GPG::Signature methods - validity(), keyid(), time()
   and trusted().

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

