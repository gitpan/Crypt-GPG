# -*-cperl-*-
#
# Crypt::GPG - An Object Oriented Interface to GnuPG.
# Copyright (c) 2000 Ashish Gulhati <hash@netropolis.org>
#
# All rights reserved. This code is free software; you can
# redistribute it and/or modify it under the same terms as Perl
# itself.
#
# $Id: GPG.pm,v 1.13 2001/05/05 11:27:07 cvs Exp $

package Crypt::GPG;

=pod

=head1 NAME 

Crypt::GPG - An Object Oriented Interface to GnuPG.

=head1 SYNOPSIS

  use Crypt::GPG;
  $gpg = new Crypt::GPG;

  $gpg->gpgbin ($path_to_gpg);     # The GnuPG executable.
  $gpg->secretkey ($keyid);        # Set ID of default secret key.
  $gpg->passphrase ($passphrase);  # Set passphrase.
  $gpg->version ($versionstring);  # Set version string.
  $gpg->comment ($commentstring);  # Set comment string.

  $gpg->text ($boolean)            # Use --textmode option.
  $gpg->signfirst ($boolean)       # When encrypting, use '--sign' option.
  $gpg->encryptsafe ($boolean);    # Switch paranoid encryption on/off.
  $gpg->armor ($boolean);          # Switch ASCII armoring on/off.
  $gpg->detach ($boolean);         # Switch detached signatures on/off.
  $gpg->gpgopts ($option);         # Extra options for the GnuPG command.

  $gpg->debug ($boolean);          # Switch debugging output on/off.

  $signed = $gpg->sign (@message);
  @recipients = $gpg->msginfo (@ciphertext);
  $ciphertext = $gpg->encrypt (\@plaintext, \@recipients);
  ($signature, $plaintext) = $gpg->decrypt (\@ciphertext, [ \@signature ]);

  $status = $gpg->keygen 
    ($name, $email, $keytype, $keysize, $expire, $passphrase);
  $gpg->addkey (\@key, $pretend);
  @keys = $gpg->keyinfo (@ids);

  (The methods below will likely be encapsulated into the
  Crypt::GPG::Key class in a future release, bewarned!)

  $key = $keys[0];
  $gpg->delkey ($key);
  $gpg->disablekey ($key);
  $gpg->enablekey ($key);
  $keystring = $gpg->export ($key);
  $gpg->keypass ($key, $oldpassphrase, $newpassphrase);

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

=cut

use Carp;
#use 5.004;
use Fcntl;
use Expect;
use strict;
use Date::Parse;
use POSIX qw( tmpnam );
use Time::HiRes qw( sleep );
use vars qw( $VERSION $AUTOLOAD );

( $VERSION ) = '$Revision: 1.13 $' =~ /\s+([\d\.]+)/;

=pod

=head1 CONSTRUCTOR

=over 2

=item B<new ()>

Creates and returns a new Crypt::GPG object.

=back

=cut

sub new {
  bless { GPGBIN         =>   'gpg',
	  GPGOPTS        =>   '--lock-multiple',
	  VERSION        =>   "Version: Crypt::GPG v$VERSION\n",
	  PASSPHRASE     =>   '',
	  COMMENT        =>   '',
	  ARMOR          =>   1,
	  DETACH         =>   1,
	  ENCRYPTSAFE    =>   1,
	  TEXT           =>   1,
	  SIGNFIRST      =>   0,
	  SECRETKEY      =>   0,
	  DEBUG          =>   1,
	}, shift;
}

=pod

=head1 DATA METHODS

=over 2

=item B<gpgbin ()>

Sets the B<GPGBIN> instance variable which gives the path to the GnuPG
binary.

=item B<gpgopts ()>

Sets the B<GPGOPTS> instance variable which may be used to pass
additional options to the GnuPG binary. For proper functioning of this
module, it is advisable to always include '--lock-multiple' in the
GPGOPTS string.

=item B<secretkey ()>

Sets the B<SECRETKEY> instance variable which may be a KeyID or a
username. This is the ID of the default key to use for signing.

=item B<passphrase ()>

Sets the B<PASSPHRASE> instance variable, required for signing and
decryption.

=item B<text ()>

Sets the B<TEXT> instance variable. If set to 1, GnuPG will use
network-compatible line endings for proper cross-platform
compatibility and the plaintext will gain a newline at the end, if it
does not already have one.

=item B<signfirst ()>

Sets the B<SIGNFIRST> instance variable. If set to 1, plaintext will
be signed before encryption. This is the way it should be done,
generally, unless you have good reason not to do it this way.

=item B<armor ()>

Sets the B<ARMOR> instance variable. If set to 0, Crypt::GPG doesn't
ASCII armor its output. Else, it does. Default is to use
ascii-armoring. I haven't tested the methods in this module without
ASCII armoring yet.

=item B<detach ()>

Sets the B<DETACH> instance variable. If set to 1, the sign method
will produce detached signature certificates, else it won't. The
default is to produce detached signatures.

=item B<encryptsafe ()>

Sets the B<ENCRYPTSAFE> instance variable. If set to 1, encryption
will fail if trying to encrypt to a key which is not trusted. This is
the default. Switch to 0 if you want to encrypt to untrusted keys.

=item B<version ()>

Sets the B<VERSION> instance variable which can be used to change the
Version: string on the GnuPG output to whatever you like.

=item B<comment ()>

Sets the B<COMMENT> instance variable which can be used to change the
Comment: string on the GnuPG output to whatever you like.

=item B<debug ()>

Sets the B<DEBUG> instance variable which causes the raw output of
Crypt::GPG's interaction with the GnuPG binary to be dumped to STDOUT.

=back

=cut

sub AUTOLOAD {
  my $self = shift; (my $auto = $AUTOLOAD) =~ s/.*:://;
  if ($auto =~ /^(passphrase|secretkey|armor|gpgbin|gpgopts|
                  detach|encryptsafe|version|comment|debug)$/x) {
    $self->{"\U$auto"} = shift;
  }
  else {
    croak "Could not AUTOLOAD method $auto.";
  }
}

=pod

=head1 OBJECT METHODS

=over 2

=item B<sign (@message)>

Signs B<@message> with the secret key specified with B<secretkey ()>
and returns the result as a string.

=cut

sub sign {
  my $self = shift; my ($secretkey, $detach, $armor) = (); my $tmpnam;
  $detach = '-b' if $self->{DETACH}; $armor = '-a' if $self->{ARMOR}; 
  $secretkey = '--default-key ' . $self->{SECRETKEY} if $self->{SECRETKEY};
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  my $message = join ('', @_); $message .= "\n" unless $message =~ /\n$/s;
  print FH $message; close FH;
  my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} -o- --sign $armor $detach $secretkey $tmpnam"); 
  $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, 'Enter passphrase:'); 
  sleep (0.2); print $expect "$self->{PASSPHRASE}\r";
  $expect->expect (undef, '-re', '-----BEGIN', '-re', 'passphrase:\s*');
  return undef if ($expect->exp_match_number==2);
  sleep (0.2); $expect->expect (undef); my $info = $expect->exp_match() . $expect->exp_before(); 
  $info =~ s/\r//sg; $info =~ s/^Version:.*\n/$self->{VERSION}/m; 
  $info =~ s/^Comment:.*\n/$self->{COMMENT}/m; $info=~s/PGP MESSAGE/PGP SIGNATURE/sg;
  return $info;
}

=pod

=item B<decrypt ( \@message, [ \@signature ])>

Decrypts and/or verifies the message in B<@message>, optionally using
the detached signature in B<@signature>, and returns the plaintext
message as a string, along with a Crypt::GPG::Signature object
corresponding to the signature on the message, if the message was
signed.

=cut

sub decrypt {
  my $self = shift; my $tmpnam; my $tmpnam2; my $tmpnam3;
  my $messageref = $_[0];
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  do { $tmpnam2 = tmpnam() } until sysopen(FH2, $tmpnam2, O_RDWR|O_CREAT|O_EXCL);
  my $message = join '', @{$messageref}; $message .= "\n" unless $message =~ /\n$/s;
  print FH $message; close FH;
  if ($_[1]) {
    my $realmessage = join '', @{$_[1]};
    do { $tmpnam3 = tmpnam() } until sysopen(FH3, $tmpnam3, O_RDWR|O_CREAT|O_EXCL);
    print FH3 $realmessage; close FH3;
  }
  my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} --yes --decrypt -o $tmpnam2 $tmpnam"); 
  $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, '-re', 'gpg:', '-re', 'passphrase:\s*',
		   '-re', 'data file:');
  if ($expect->exp_match_number==3) {
    sleep (0.2); print $expect "$tmpnam3\r";
    $expect->expect (undef, '-re', 'gpg:', '-re', 'passphrase:\s*');
  }
  if ($expect->exp_match_number==2) {
    sleep (0.2); print $expect "$self->{PASSPHRASE}\r";
    $expect->expect (undef, '-re', '^gpg:', '-re', 'passphrase:\s*');
    close FH2, unlink $tmpnam, $tmpnam2, return undef if ($expect->exp_match_number==2)
  }
  sleep (0.2); $expect->expect (undef); 
  my $info = $expect->exp_match() . $expect->exp_before(); 
  unlink $tmpnam, $tmpnam3;
  $info =~ s/\r//sg;
  my $trusted = ($info !~ /WARNING: This key is not certified/s);
  my $unknown = ($info =~ /Can't check signature: public key not found/s);
  $message = join ('',<FH2>); close FH2; unlink $tmpnam2;
  return ($message) 
    unless $info =~ /.*Signature\ made\ ((?:\S+\s+){6})using\ \S+\ key\ ID\ (\S+)
	             \s*gpg:\ (Good|BAD)\ signature\ from/sx;;
  my $signature = {'Validity' => $3, 'KeyID' => $2, 'Time' => $1, 'Trusted' => $trusted};
  $signature->{Time} =~ s/\S+\s*$//; $signature->{Time} = str2time ($signature->{Time}, $1); 
  bless $signature, 'Crypt::GPG::Signature';
  return ($message, $signature);
}

=pod

=item B<msginfo (@ciphertext)>

Returns a list of the recipient key IDs that B<@ciphertext> is
encrypted to.

=cut

sub msginfo {
  my $self = shift; my @return = (); my $tmpnam; 
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  print FH join '',@$_[0]; close FH;
  my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} --batch $tmpnam"); 
  $expect->log_stdout($self->{DEBUG});
  sleep (0.2); $expect->expect (undef); my $info = $expect->exp_before();
  $info =~ s/key, ID (.{8})/{push @return, $1}/sge; unlink $tmpnam;
  return @return;
}

=pod

=item B<encrypt ($plaintext, $keylist [, -sign] [, -text] )>

Encrypts B<$plaintext> with the public keys of the recipients listed
in B<$keylist> and returns the result in a string, or B<undef> if
there was an error while processing. Returns undef if any of the keys
are not found.

Either $plaintext or $keylist may be specified as either an arrayref 
or a simple scalar.  If $plaintext is a an arrayref, it will be
join()ed without newlines. 

If the -sign option is provided, the message will be signed then 
encrypted. 

If the -text option is specified, GnuPG will use network-compatible
line endings for proper cross-platform compatibility.  In this case,
the plaintext will gain a newline at the end, if it does not already
have one.

=cut

sub encrypt {
  my $self = shift; my $info = ''; my $tmpnam; my ($message, $rcpts) = @_;
  my $comment = "--comment '$self->{COMMENT}'";
  my ($sign, $text); while( $#_ > 1 ) { 
    my $parm = pop; 
    $sign = $parm if $parm eq '-sign';
    $text = $parm if $parm eq '-text';
  }
  $sign = '--sign' if $sign; $text = '--textmode' if $text;
  my $armor = "-a" if $self->{ARMOR}; 
  $rcpts = "-r $rcpts" 				unless 	ref($rcpts) eq 'ARRAY';
  $rcpts = join ( ' ', map ("-r$_", @$rcpts) )	if 	ref($rcpts) eq 'ARRAY';
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  $message = join ('', @$message) if (ref $message eq 'ARRAY' ); 
  $message .= "\n" if( $text && $message !~ /\n$/s ); 
  print FH $message; close FH;
  my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} $comment -o- --encrypt $sign $armor $rcpts $tmpnam"); 
  $expect->log_stdout($self->{DEBUG});
  while (1) {
    $expect->expect (undef, '-re', '-----BEGIN PGP', 'Use this key anyway?', 'key not found');
    if ($expect->exp_match_number==2) {
      sleep (0.2);
      if ($self->{ENCRYPTSAFE}) {
	print $expect "n\n";
	$expect->expect (undef);
	return undef;
      }
      else {
	print $expect "y\n";
      }	
    }
    elsif ($expect->exp_match_number==3) {
      unlink $tmpnam, return undef;
    }
    else {
      $info = $expect->exp_match();
      last;
    }
  }
  sleep (0.2); $expect->expect (undef);
  $info .= $expect->exp_before(); $info =~ s/.*\n(-----BEGIN)/$1/s;
  $info =~ s/\r//sg; $info =~ s/^Version:.*\n/$self->{VERSION}/m; 
  unlink $tmpnam;
  return $info;
}

=pod

=item B<addkey (\@key, $pretend)>

Adds the keys given in B<@key> to the user's key ring and returns a
list of Crypt::GPG::Key objects corresponding to the keys that were
added. If B<$pretend> is true, it pretends to add the key and creates
the key object, but doesn't actually perform the key addition.

=cut

sub addkey {
  my $self = shift; my $key = shift; my $pretend = shift; my $tmpnam; my $tmpnam2; my $tmpnam3;
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  print FH join '', @$key; close FH; 
  do { $tmpnam2 = tmpnam() } until sysopen(FH2, $tmpnam2, O_RDWR|O_CREAT|O_EXCL);
  do { $tmpnam3 = tmpnam() } until sysopen(FH3, $tmpnam3, O_RDWR|O_CREAT|O_EXCL);
  my $pret = "--options /dev/null --no-default-keyring --keyring $tmpnam2 --secret-keyring $tmpnam3";
  unless ($pretend) {
    my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} -v --import $tmpnam"); 
    $expect->log_stdout($self->{DEBUG}); $expect->expect (undef);
  }
  my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} $pret -v --import $tmpnam"); 
  $expect->log_stdout($self->{DEBUG}); $expect->expect (undef);
  my $info = $expect->exp_before(); unlink $tmpnam; my $fp = '--fingerprint ' x 2;
  my @keylist = `$self->{GPGBIN} $self->{GPGOPTS} $pret --check-sigs $fp --with-colons`;
  my @seclist = `$self->{GPGBIN} $self->{GPGOPTS} $pret --list-secret-keys $fp --with-colons`;
  close FH2, close FH3, unlink $tmpnam2, $tmpnam3;
  $self->parsekeys (@keylist[2..$#keylist], @seclist[2..$#seclist]);
}

=pod

=item B<export ($key)>

Exports the key specified by the Crypt::GPG::Key object B<$key> and
returns the result as a string.

=cut

sub export {
  my $self = shift; my $key = shift; my $armor; $armor = "-a" if $self->{ARMOR}; 
  my $id = $key->{ID}; my $secret = '-secret-keys' if $key->{Type} eq 'sec';
  my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} --export$secret $armor $id"); 
  $expect->log_stdout($self->{DEBUG});
  sleep (0.2); $expect->expect (undef); my $info = $expect->exp_before();
  $info =~ s/\r//sg; $info =~ s/^Version:.*\n/$self->{VERSION}/m; 
  $info =~ s/^Comment:.*\n/$self->{COMMENT}/m;
  return $info;
}

=pod

=item B<keygen ($name, $email, $keytype, $keysize, $expire, $passphrase)>

Creates a new keypair with the parameters specified. The only
supported B<$keytype> is 'ELG-E'. B<$keysize> can be any of 768, 1024,
2048, 3072 or 4096. Returns undef if there was an error, otherwise
returns a filehandle that reports the progress of the key generation
process similar to the way GnuPG does. The key generation is not
complete till you read an EOF from the returned filehandle.

=cut

sub keygen {
  my $self = shift; my ($name, $email, $keytype, $keysize, $expire, $pass) = @_;
  return undef if $keysize < 768 or $keysize > 4096 or $keytype ne 'ELG-E' or length ($name) < 5; 
  return undef if $email and $email !~ /^[\w\.\-]+\@[\w\.\-]+\.[\w.\-]+$/;
  my $bigkey = ($keysize > 1536);

  my $pid = open(GPG, "-|");
  return undef unless (defined $pid);
  if ($pid) {
    $SIG{CHLD} = 'IGNORE';
    return \*GPG;
  }
  else {
    my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} --gen-key"); $expect->log_stdout(0);
    $expect->expect (undef, 'selection?'); sleep (0.2); print $expect ( "1\r"); print ".\n";
    $expect->expect (undef, 'do you want?'); sleep (0.2); print $expect ("$keysize\r"); print ".\n";
    $expect->expect (undef, 'keysize?'), sleep (0.2), print $expect ("y\r"), print ".\n" if $bigkey;
    $expect->expect (undef, 'valid for?'); sleep (0.2); print $expect ("$expire\r"); print ".\n";
    $expect->expect (undef, '(y/n)?'); sleep (0.2); print $expect ("y\r"); print ".\n";
    $expect->expect (undef, 'name:'); sleep (0.2); print $expect ("$name\r"); print ".\n"; 
    $expect->expect (undef, 'address:'); sleep (0.2); print $expect ("$email\r"); print ".\n";
    $expect->expect (undef, 'Comment:'); print $expect ("\r"); print ".\n";
    $expect->expect (undef, 'uit?'); sleep (0.2); print $expect ("o\r"); print ".\n";
    $expect->expect (undef, 'phrase: '); sleep (0.2); print $expect ("$pass\r"); print ".\n";
    $expect->expect (undef, 'phrase: '); sleep (0.2); print $expect ("$pass\r"); print ".\n";
    $expect->expect (undef, '-re', '([\+\.\>\<\^]|created and signed)');
    my $x = $expect->exp_match(); 
    while ($x !~ /created and signed/) {
      print "$x\n";
      my $t = $expect->expect (2, '-re', '([\+\.\>\<\^]|created and signed)');
      $x = $expect->exp_match(); $x = '.' unless $t;
    }	
    print "|\n";
    sleep (0.2); $expect->expect (undef, 'nothing.');
    exit();
  }
}

=pod

=item B<keyinfo (@keyids)>

Returns an array of Crypt::GPG::Key objects corresponding to the Key
IDs listed in B<@keyids>.

=cut

sub keyinfo {
  my $self = shift; my $ids = join ' ',@_; my $fp = '--fingerprint ' x 2;
  my @keylist = `$self->{GPGBIN} $self->{GPGOPTS} --check-sigs $fp --with-colons $ids`; 
  my @seclist = `$self->{GPGBIN} $self->{GPGOPTS} --list-secret-keys $fp --with-colons $ids`; 
  @keylist = grep { /^...:.*:$/ } (@keylist, @seclist);
  $self->parsekeys (@keylist);
}

=pod

=item B<parsekeys (@keylist)>

Parses a raw GnuPG formatted key listing in B<@keylist> and returns an
array of Crypt::GPG::Key objects.

=cut

sub parsekeys {
  my $self=shift; my @keylist = @_;
  my @keys; my ($i, $subkey, $subnum, $uidnum) = (-1);
  foreach (@keylist) {
    if (/^(pub|sec)/) {
      $uidnum=-1; $subnum=-1; $subkey=0;
      my ($type, $u1, $size, $algorithm, $id, $created, $expires, $u2, $u3, $uid)
	= split (':');
      $keys[++$i] = { 
		     Type       =>    $type,
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

=pod

=item B<keypass ($key, $oldpass, $newpass)>

Change the passphrase for a key. Returns true if the passphrase change
succeeded, false if not, or undef if there was an error.

=cut

sub keypass {
  my $self = shift; my ($key, $oldpass, $newpass) = @_;
  return unless $key->{Type} eq 'sec'; return undef unless $newpass;
  my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} --edit-key $key->{ID}"); 
  $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, 'Command>'); sleep (0.2); print $expect ("passwd\r"); 
  $expect->expect (undef, 'phrase: '); sleep (0.2); print $expect ("$oldpass\r"); 
  $expect->expect (undef, 'please try again', 'phrase: '); 
  return undef if $expect->exp_match_number==1; sleep (0.2); print $expect ("$newpass\r"); 
  $expect->expect (undef, 'phrase: '); sleep (0.2); print $expect ("$newpass\r"); 
  $expect->expect (undef, 'Command>'); sleep (0.2); print $expect ("quit\r"); 
  $expect->expect (undef, 'changes?'); sleep (0.2); print $expect ("y\r"); 
  sleep (0.2); $expect->expect (undef);
  return 1;
}

=pod

=item B<delkey ($keyid)>

Deletes the key specified by the Crypt::GPG::Key object B<$key> from
the user's key ring. Returns undef if there was an error, or 1 if the
key was successfully deleted.

=cut

sub delkey {
  my $self = shift; my $key = shift; 
  my $del = $key->{Type} eq 'sec'?'--delete-secret-key':'delete-key';
  my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} $del $key->{ID}"); 
  $expect->log_stdout($self->{DEBUG}); $expect->expect (undef, 'delete it first.', 'keyring?'); 
  return undef if ($expect->exp_match_number==1); sleep (0.2); print $expect ("y\r"); 
  if ($key->{Type} eq 'sec') {
    $expect->expect (undef, 'really delete?'); sleep (0.2), print $expect ("y\r");
  }
  $expect->expect (undef);
  return 1;
}

=pod

=item B<disablekey ($keyid)>

Disables the key specified by the Crypt::GPG::Key object B<$key>.

=cut

sub disablekey {
  my $self = shift; my $key = shift;
  my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} --edit-key $key->{ID}"); 
  $expect->log_stdout($self->{DEBUG}); $expect->expect (undef, 'been disabled', 'Command>'); 
  return undef if $expect->exp_match_number==1; sleep (0.2); print $expect ("disable\r"); 
  $expect->expect (undef, 'Command>'); sleep (0.2); print $expect ("quit\r"); 
  $expect->expect (undef, 'changes?'); sleep (0.2); print $expect ("y\r"); 
  sleep (0.2); $expect->expect (undef);
  return 1;
}

=pod

=item B<enablekey ($keyid)>

Enables the key specified by the Crypt::GPG::Key object B<$key>.

=cut

sub enablekey {
  my $self = shift; my $key = shift;
  my $expect = Expect->spawn ("$self->{GPGBIN} $self->{GPGOPTS} --edit-key $key->{ID}"); 
  $expect->log_stdout($self->{DEBUG}); $expect->expect (undef, 'been disabled', 'Command>'); 
  return undef unless $expect->exp_match_number==1; sleep (0.2); print $expect ("enable\r"); 
  $expect->expect (undef, 'Command>'); sleep (0.2); print $expect ("quit\r"); 
  $expect->expect (undef, 'changes?'); sleep (0.2); print $expect ("y\r"); 
  sleep (0.2); $expect->expect (undef);
  return 1;
}

=pod

=back

=head1 BUGS

=over 2

=item * 

Error checking needs work. 

=item * 

Some key manipulation functions are missing. 

=item * 

The method call interface is subject to change in future versions,
specifically, key manipulation methods will be encapsulated into the
Crypt::GPG::Key class in a future version.

=item * 

The current implementation will probably eat up all your RAM if you
try to operate on huge messages. In future versions, this will be
addressed by reading from and returning filehandles, rather than using
in-core data.

=back

=item * 

Methods may break if you don't use ASCII armoring.

=back

=head1 AUTHOR

Crypt::GPG is Copyright (c) 2000 Ashish Gulhati
<hash@netropolis.org>. All Rights Reserved.

=head1 ACKNOWLEDGEMENTS

Thanks to Barkha for inspiration and lots of laughs, and to the GnuPG
team.

=head1 LICENSE

This code is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 DISCLAIMER

This is free software. If it breaks, you own both parts.

=cut

'True Value';
