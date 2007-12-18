package re::engine::PCRE;
use 5.009005;
use XSLoader ();

# All engines should subclass the core Regexp package
our @ISA = 'Regexp';

BEGIN
{
    $VERSION = '0.13';
    XSLoader::load __PACKAGE__, $VERSION;
}

sub import
{
    $^H{regcomp} = ENGINE;
}

sub unimport
{
    delete $^H{regcomp}
        if $^H{regcomp} == ENGINE;
}

1;

__END__

=head1 NAME 

re::engine::PCRE - Perl-compatible regular expression engine

=head1 SYNOPSIS

    use re::engine::PCRE;

    if ("Hello, world" =~ /(?<=Hello|Hi), (world)/) {
        print "Greetings, $1!";
    }

=head1 DESCRIPTION

Replaces perl's regex engine in a given lexical scope with PCRE
regular expressions provided by libpcre. Currently version 7.2 of PCRE
is shipped with the module.

=head1 AUTHORS

E<AElig>var ArnfjE<ouml>rE<eth> Bjarmason <avar@cpan.org>

=head1 COPYRIGHT

Copyright 2007 E<AElig>var ArnfjE<ouml>rE<eth> Bjarmason.

The original version was copyright 2006 Audrey Tang
E<lt>cpan@audreyt.orgE<gt> and Yves Orton.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

The included F<libpcre> by I<Philip Hazel> is under a BSD-style
license. See the F<LICENCE> file for details.

=cut
