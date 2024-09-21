#ifndef SFUNC
#error "define SFUNC"
#endif

#define SFUNC1(x) SFUNC(x, #x)
#define ACCESSOR(x) SFUNC1(x) SFUNC(x##_set, #x "=")

SFUNC1(Argonaut)
SFUNC1(JSON)
SFUNC1(ParseError)
SFUNC1(SerializationError)
SFUNC1(AssertFailed)
SFUNC1(Options)
SFUNC1(new)
SFUNC1(DEFAULT)
SFUNC1(default)
SFUNC1(MINIFIED)
SFUNC1(minified)
SFUNC1(to_json)
SFUNC1(parse)
SFUNC1(inspect)
SFUNC1(to_s)
SFUNC(jsonmarker_symbol, "@@jm:symbol")
SFUNC(jsonmarker_object, "@@jm:object")
ACCESSOR(indent_width)
ACCESSOR(symbolize_keys)
ACCESSOR(symbol_ext)
ACCESSOR(object_ext)
ACCESSOR(space_in_empty)
ACCESSOR(minify)
ACCESSOR(integer_lits)
ACCESSOR(slurp)
SFUNC1(__true_str)
SFUNC1(__false_str)
SFUNC1(__null_str)

#undef SFUNC1
