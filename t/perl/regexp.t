#!./perl

#use Test::More skip_all => "Not run by default, remove this line to 

# The tests are in a separate file 't/op/re_tests'.
# Each line in that file is a separate test.
# There are five columns, separated by tabs.
#
# Column 1 contains the pattern, optionally enclosed in C<''>.
# Modifiers can be put after the closing C<'>.
#
# Column 2 contains the string to be matched.
#
# Column 3 contains the expected result:
# 	y	expect a match
# 	n	expect no match
# 	c	expect an error
#	B	test exposes a known bug in Perl, should be skipped
#	b	test exposes a known bug in Perl, should be skipped if noamp
#
# Columns 4 and 5 are used only if column 3 contains C<y> or C<c>.
#
# Column 4 contains a string, usually C<$&>.
#
# Column 5 contains the expected result of double-quote
# interpolating that string after the match, or start of error message.
#
# Column 6, if present, contains a reason why the test is skipped.
# This is printed with "skipped", for harness to pick up.
#
# \n in the tests are interpolated, as are variables of the form ${\w+}.
#
# Blanks lines are treated as PASSING tests to keep the line numbers
# linked to the test number.
#
# If you want to add a regular expression test that can't be expressed
# in this format, don't add it here: put it in op/pat.t instead.
#
# Note that columns 2,3 and 5 are all enclosed in double quotes and then
# evalled; so something like a\"\x{100}$1 has length 3+length($1).

my $file;
BEGIN {
    $iters = shift || 1;	# Poor man performance suite, 10000 is OK.

    # Do this open before any chdir
    $file = shift;
    if (defined $file) {
	open TESTS, $file or die "Can't open $file";
    }
}

use strict;
use warnings FATAL=>"all";
use vars qw($iters $numtests $bang $ffff $nulnul $OP);
use vars qw($skip_amp $qr $qr_embed); # set by our callers
use re::engine::PCRE ();
use Data::Dumper;

if (!defined $file) {
    open(TESTS,'re_tests') || open(TESTS,'t/re_tests') || open(TESTS,'t/perl/re_tests')
}

my @tests = <TESTS>;

close TESTS;

$bang = sprintf "\\%03o", ord "!"; # \41 would not be portable.
$ffff  = chr(0xff) x 2;
$nulnul = "\0" x 2;
$OP = $qr ? 'qr' : 'm';

$| = 1;
printf "1..%d\n# $iters iterations\n", scalar @tests;
my $test;
my $skip_rest;


# Tests known to fail under PCRE
my %pcre_fail;
my @pcre_fail = (
    # Pathological patterns that run into PCRE_ERROR_MATCHLIMIT
    813 .. 830,

    # err: [a-[:digit:]] => range out of order in character class
    835,

    # aba =~ ^(a(b)?)+$ and aabbaa =~ ^(aa(bb)?)+$
    867 .. 868,

    # err: (?!)+ => nothing to repeat
    970,

    # XXX: <<<>>> pattern
    1021,

    # XXX: Some named capture error
    1050 .. 1051,

    # (*F) / (*FAIL)
    1191, 1192,

    # (*A) / (*ACCEPT)
    1194 .. 1195,

    # (?'${number}$optional_stuff' key names)
    1217 .. 1223,

    # XXX: Some named capture error
    1253,

    # XXX: \R doesn't match an utf8::upgraded \x{85}, we need to
    # always convert the subject and pattern to utf-8 for these cases
    # to work
    1291, 1293 .. 1296,

    # These cause utf8 warnings, see above
    1307, 1309, 1310, 1311, 1312, 1318, 1320 .. 1323,
);
@pcre_fail{@pcre_fail} = ();

TEST:
foreach (@tests) {
    $test++;
    if (!/\S/ || /^\s*#/) {
        print "ok $test # (Blank line or comment)\n";
        if (/\S/) { print $_ };
        next;
    }
    if (/\(\?\{/ || /\(\?\?\{/) {
        print "ok $test # (PCRE doesn't support (?{}) or (??{}))\n";
        if (/\S/) { print $_ };
        next;
    }
    if (exists $pcre_fail{$test}) {
        print "ok $test # Known to fail under PCRE\n";
        next;
    }
    $skip_rest = 1 if /^__END__$/;

    if ($skip_rest) {
        print "ok $test # (skipping rest)\n";
        next;
    }
    chomp;
    s/\\n/\n/g;
    my ($pat, $subject, $result, $repl, $expect, $reason) = split(/\t/,$_,6);
    $reason = '' unless defined $reason;
    my $input = join(':',$pat,$subject,$result,$repl,$expect);
    $pat = "'$pat'" unless $pat =~ /^[:'\/]/;
    $pat =~ s/(\$\{\w+\})/$1/eeg;
    $pat =~ s/\\n/\n/g;
    $subject = eval qq("$subject"); die $@ if $@;
    $expect  = eval qq("$expect"); die $@ if $@;
    $expect = $repl = '-' if $skip_amp and $input =~ /\$[&\`\']/;
    my $skip = ($skip_amp ? ($result =~ s/B//i) : ($result =~ s/B//));
    $reason = 'skipping $&' if $reason eq  '' && $skip_amp;
    $result =~ s/B//i unless $skip;

    for my $study ('', 'study $subject', 'utf8::upgrade($subject)',
		   'utf8::upgrade($subject); study $subject') {
	# Need to make a copy, else the utf8::upgrade of an alreay studied
	# scalar confuses things.
	my $subject = $subject;
	my $c = $iters;
	my ($code, $match, $got);
        if ($repl eq 'pos') {
            $code= <<EOFCODE;
                $study;
                pos(\$subject)=0;
                \$match = ( \$subject =~ m${pat}g );
                \$got = pos(\$subject);
EOFCODE
        }
        elsif ($qr_embed) {
            $code= <<EOFCODE;
                my \$RE = qr$pat;
                $study;
                \$match = (\$subject =~ /(?:)\$RE(?:)/) while \$c--;
                \$got = "$repl";
EOFCODE
        }
        else {
            $code= <<EOFCODE;
                $study;
                \$match = (\$subject =~ $OP$pat) while \$c--;
                \$got = "$repl";
EOFCODE
        }
	{
	    # Probably we should annotate specific tests with which warnings
	    # categories they're known to trigger, and hence should be
	    # disabled just for that test
	    no warnings qw(uninitialized regexp);
        eval "BEGIN { \$^H{regcomp} = re::engine::PCRE->ENGINE; }; $code"
        #eval $code; # use perl's engine
	}
	chomp( my $err = $@ );
	if ($result eq 'c' && $err) {
	    #if ($err !~ m!^\Q$expect!) { print "not ok $test (compile) $input => `$err'\n"; next TEST }
	    last;  # no need to study a syntax error
	}
	elsif ( $skip ) {
	    print "ok $test # skipped", length($reason) ? " $reason" : '', "\n";
	    next TEST;
	}
	elsif ($@) {
	    print "not ok $test $input => error `$err'\n$code\n$@\n"; next TEST;
	}
	elsif ($result eq 'n') {
	    if ($match) { print "not ok $test ($study) $input => false positive\n"; next TEST }
	}
	else {
	    if (!$match || $got ne $expect) {

#	        eval { require Data::Dumper };
#		if ($@) {
#		    print "not ok $test ($study) $input => `$got', match=$match\n$code\n";
#		}
#		else { # better diagnostics
		    my $s = Data::Dumper->new([$subject],['subject'])->Useqq(1)->Dump;
		    my $g = Data::Dumper->new([$got],['got'])->Useqq(1)->Dump;
		    print "not ok $test ($study) $input => `$got', match=$match\n$s\n$g\n$code\n";
#		}

		next TEST;
	    }
	}
    }
    print "ok $test\n";
}

1;
