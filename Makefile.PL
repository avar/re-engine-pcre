use 5.009005;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME		  => 're::engine::PCRE',
    AUTHOR        => 'Ævar Arnfjörð Bjarmason <avar@cpan.org>',
    VERSION_FROM  => 'PCRE.pm',
    ABSTRACT_FROM => 'PCRE.pm',
    LICENSE       => 'perl',
    LIBS          => [ '-lpcre' ],
);
