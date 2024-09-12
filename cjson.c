/* -*- c-mode -*- */
#include "dragonruby.h"
#include "mruby.h"
#include "mruby/array.h"
#include "mruby/istruct.h"
#include "mruby/value.h"
#include <math.h>
#include <stdint.h>
#include <string.h>

#define EVAL(...) EVAL16(__VA_ARGS__)
#define EVAL16(...) EVAL8(EVAL8(__VA_ARGS__))
#define EVAL8(...) EVAL4(EVAL4(__VA_ARGS__))
#define EVAL4(...) EVAL2(EVAL2(__VA_ARGS__))
#define EVAL2(...) EVAL1(EVAL1(__VA_ARGS__))
#define EVAL1(...) __VA_ARGS__
#define DEFER1(m) m EMPTY()
#define EMPTY()
#define _MAP2s(func, a, b, c, ...)                                             \
  func(a, b, c);                                                               \
  __VA_OPT__(DEFER1(__MAP2s)()(func, a, b, __VA_ARGS__))

#define __MAP2s() _MAP2s

#define MAP(...) EVAL(_MAP2s(__VA_ARGS__))

#define usym(name) usym__##name
#define usymv(name) usym(val__##name)
#define declare_usym(name)                                                     \
  mrb_sym usym(name);                                                          \
  mrb_value usymv(name)
#define init_usym2(mrb, declname, symname)                                     \
  usym(declname) = mrb_intern_lit(mrb, symname);                               \
  usymv(declname) = mrb_symbol_value(usym(declname))
#define init_usym(mrb, name) init_usym2(mrb, name, #name)

#define SFUNC(name, _) declare_usym(name);
#include "symbols.inc"
#undef SFUNC

struct json_opts_t {
  uint8_t indent_width;
  uint8_t indent_depth;
  struct {
    uint8_t symbolize_keys : 1;
    uint8_t sym_ext : 1;
    uint8_t obj_ext : 1;
    uint8_t spc_nul : 1;
    uint8_t minify : 1;
    uint8_t int_lit_int : 1;
    uint8_t slurp : 1;
  };
};

#define alloc_init_json_opts_val(MRB, VAR, INITER)                             \
  do {                                                                         \
    struct RIStruct *VAR##_rb = (struct RIStruct *)mrb_obj_alloc(              \
        MRB, MRB_TT_ISTRUCT, json_opts_class);                                 \
    *(struct json_opts_t *)VAR##_rb->inline_data = INITER;                     \
    VAR = mrb_obj_value(VAR##_rb);                                             \
  } while (0)

#define unwrap_istruct_json_opts(var) (struct json_opts_t *)mrb_istruct_ptr(var)

static_assert(sizeof(struct json_opts_t) <= ISTRUCT_DATA_SIZE);

struct json_opts_t default_opts = {.indent_width = 4,
                                   .indent_depth = 0,
                                   .symbolize_keys = 0,
                                   .sym_ext = 0,
                                   .obj_ext = 0,
                                   .spc_nul = 0,
                                   .minify = 0,
                                   .int_lit_int = 0,
                                   .slurp = 0};

mrb_value default_opts_val;

struct json_opts_t minify_opts = {.indent_width = 0,
                                  .indent_depth = 0,
                                  .symbolize_keys = 0,
                                  .sym_ext = 0,
                                  .obj_ext = 0,
                                  .spc_nul = 0,
                                  .minify = 1,
                                  .int_lit_int = 0,
                                  .slurp = 0};

mrb_value minify_opts_val;

static struct RClass *parse_error_class;
static struct RClass *json_opts_class;

#define DCJ_MAX_NESTING 256

struct dcj_parsing_ctx {
  const char *str;
  const char *stri;
  const char *send;
  const char *obeg;
  mrb_value co;
  const struct json_opts_t *opts;
  struct {
    uint8_t parsing_key : 1;
    uint8_t tosym : 1;
  };
};

mrb_value dcj_json_opts_newc(mrb_state *mrb, struct json_opts_t opts) {
  mrb_value instance;
  alloc_init_json_opts_val(mrb, instance, opts);
  return instance;
}

mrb_value dcj_json_opts_new_m(mrb_state *mrb, mrb_value) {
  const mrb_sym s_table[] = {usym(indent_width),   usym(symbolize_keys),
                             usym(symbol_ext),     usym(object_ext),
                             usym(space_in_empty), usym(minify),
                             usym(integer_lits),   usym(slurp)};
  mrb_value values[8];
  mrb_kwargs kws = {.values = values,
                    .num = 8,
                    .required = 0,
                    .rest = nullptr,
                    .table = s_table};

  mrb_get_args(mrb, ":", &kws);

  mrb_value optsv;
  alloc_init_json_opts_val(mrb, optsv, default_opts);

  struct json_opts_t *opts = unwrap_istruct_json_opts(optsv);

  if (!mrb_undef_p(values[0])) {
    opts->indent_width = mrb_int(mrb, values[0]);
  }
  if (!mrb_undef_p(values[1])) {
    opts->symbolize_keys = mrb_test(values[1]);
  }
  if (!mrb_undef_p(values[2])) {
    opts->sym_ext = mrb_test(values[2]);
  }
  if (!mrb_undef_p(values[3])) {
    opts->obj_ext = mrb_test(values[3]);
  }
  if (!mrb_undef_p(values[4])) {
    opts->spc_nul = mrb_test(values[4]);
  }
  if (!mrb_undef_p(values[5])) {
    opts->minify = mrb_test(values[5]);
  }
  if (!mrb_undef_p(values[6])) {
    opts->int_lit_int = mrb_test(values[6]);
  }
  if (!mrb_undef_p(values[7])) {
    opts->slurp = mrb_test(values[7]);
  }

  return optsv;
}

mrb_value dcj_json_opts_inspect(mrb_state *mrb, mrb_value self) {
  struct json_opts_t opts = *unwrap_istruct_json_opts(self);
  mrb_value rbool[2] = {mrb_false_value(), mrb_true_value()};
  return mrb_format(
      mrb,
      "%T { indent_width: %i, symbolize_keys: %v, symbol_ext: %v, object_ext: "
      "%v, space_in_empty: %v, minify: %v, integer_lits: %v, slurp: %v }",
      self, (mrb_int)opts.indent_width, rbool[opts.symbolize_keys],
      rbool[opts.sym_ext], rbool[opts.obj_ext], rbool[opts.spc_nul],
      rbool[opts.minify], rbool[opts.int_lit_int], rbool[opts.slurp]);
}

mrb_value dcj_json_opts_default(mrb_state *, mrb_value) {
  return default_opts_val;
}

mrb_value dcj_json_opts_minify(mrb_state *, mrb_value) {
  return minify_opts_val;
}

static _Bool dcj_is_whitespace(const char c) {
  return c == 0x09 || c == 0x0a || c == 0x0d || c == 0x20;
}

static _Bool dcj_is_digit(const char c) { return c >= '0' && c <= '9'; }

static _Bool dcj_is_simplestring_c(const char c) {
  return (uint8_t)c >= 0x20 && c != '"' && c != '\\';
}

[[noreturn]] mrb_value dcj_notimpl(mrb_state *mrb, mrb_value self) {
  mrb_sym mid = mrb->c->ci->mid;

  if (mrb_class_p(self) || mrb_module_p(self)) {
    mrb_raisef(mrb, E_NOTIMP_ERROR, "%C.%n is not yet implemented",
               mrb_class_ptr(self), mid);
  } else {
    mrb_raisef(mrb, E_NOTIMP_ERROR, "%Y#%n is not yet implemented", self, mid);
  }
}

mrb_value dcj_parse_value(mrb_state *mrb, struct dcj_parsing_ctx *ctx);

#define dcj_parser_peek(ctx) (((ctx)->stri < (ctx)->send) ? *(ctx)->stri : 0)
#if 1
#define dcj_parser_adv(ctx) ((ctx)->stri < (ctx)->send && ++(ctx)->stri)
#else
#define dcj_parser_adv(ctx) ++(ctx)->stri
#endif

#define dcj_buffer_remaining(ctx) ((ctx)->send - (ctx)->stri)
#define dcj_past_end(ctx) ((ctx)->stri >= (ctx)->send)

// crimes!
#define dcj_parser_match(ctx, chr)                                             \
  (dcj_parser_peek(ctx) == (chr) ? dcj_parser_adv(ctx) : 0)

#define dcj_parser_match_noadv(ctx, chr) \
  (dcj_parser_peek(ctx) == (chr) ? 1 : 0)

#define dcj_parser_expect(mrb, ctx, chr)                                       \
  do {                                                                         \
    typeof(ctx) _ctx_ = (ctx);                                                 \
    char _chr_ = (chr);                                                        \
    if (!dcj_parser_match(_ctx_, _chr_)) {                                     \
      dcj_parser_raise_unexpected(mrb, _ctx_, DCJ_UT_EXP_CHR, _chr_);          \
    }                                                                          \
  } while (0)

// don't mutate ctx pls
#define dcj_parser_match_fn(ctx, pred)                                         \
  (pred(dcj_parser_peek(ctx)) ? dcj_parser_adv(ctx) : 0)

#define dcj_parser_match_noadv_fn(ctx, pred)                                   \
  (pred(dcj_parser_peek(ctx)) ? 1 : 0)

void dcj_skip_whitespace(struct dcj_parsing_ctx *ctx) {
  while (dcj_is_whitespace(dcj_parser_peek(ctx)))
    dcj_parser_adv(ctx);
}

enum unexpected_reason : uint8_t {
  DCJ_UT_EXP_VAL,
  DCJ_UT_EXP_STR,
  DCJ_UT_UEXP_CC,
  DCJ_UT_EXP_NUM,
  DCJ_UT_EXP_ESC,
  DCJ_UT_EXP_EOF,
  DCJ_UT_UEXP_EOF,
  DCJ_UT_EXP_CHR,
  DCJ_UT_EXP_HEX,
  DCJ_UT_EXP_LSP,
  DCJ_UT_UEXP_HS,
  DCJ_UT_EXP_CSP,
};

/* this will require betterment */

[[noreturn]] void dcj_parser_raise_unexpected(mrb_state *mrb,
                                              struct dcj_parsing_ctx *ctx,
                                              enum unexpected_reason reason,
                                              char chr) {
#define raisefmt_char_int "'%c' [%d]"
#define char_int                                                               \
  (dcj_parser_peek(ctx)), ((mrb_int)(dcj_parser_peek(ctx) & 0xff))
  switch (reason) {
  case DCJ_UT_EXP_VAL:
    // buggy, fix it later
    mrb_raisef(mrb, parse_error_class,
               "expected a json value begin char (/[tfn\\{\\[0-9\"]/) "
               "got " raisefmt_char_int,
               char_int);
  case DCJ_UT_EXP_STR:
    mrb_raisef(mrb, parse_error_class,
               "expected a (string) '\"' got " raisefmt_char_int, char_int);
  case DCJ_UT_EXP_NUM:
    mrb_raisef(mrb, parse_error_class,
               "expected a number got " raisefmt_char_int, char_int);
  case DCJ_UT_EXP_ESC:
    mrb_raisef(mrb, parse_error_class,
               "expected a string escape char, got " raisefmt_char_int,
               char_int);
  case DCJ_UT_EXP_EOF:
    mrb_raisef(mrb, parse_error_class, "expected eof got " raisefmt_char_int,
               char_int);
  case DCJ_UT_UEXP_EOF:
    mrb_raise(mrb, parse_error_class, "unexpected eof");
  case DCJ_UT_EXP_CHR:
    mrb_raisef(mrb, parse_error_class, "epected '%c' got " raisefmt_char_int,
               chr, char_int);
  case DCJ_UT_UEXP_CC:
    mrb_raisef(mrb, parse_error_class,
               "unexpected control character " raisefmt_char_int, char_int);
  case DCJ_UT_EXP_HEX:
    mrb_raisef(mrb, parse_error_class,
               "expected hex digit [0-9a-fA-F] got " raisefmt_char_int,
               char_int);
  case DCJ_UT_UEXP_HS:
    mrb_raisef(mrb, parse_error_class, "unexpected high surrogate");
  case DCJ_UT_EXP_CSP:
    mrb_raisef(mrb, parse_error_class, "expected complementary surrogate");
  case DCJ_UT_EXP_LSP:
    mrb_raisef(mrb, parse_error_class,
               "low surrogate not in low surrogate range");
  }
}

static uint8_t hexlut[256] = {[0 ... sizeof(hexlut) - 1] = -1};

static uint8_t dcj_hextoi(const char c) { return hexlut[(uint8_t)c]; }

static size_t dcj_parse_hex_esc(mrb_state *mrb, struct dcj_parsing_ctx *ctx,
                                char buf[4]) {
  if (dcj_buffer_remaining(ctx) < 3) {
    dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_UEXP_EOF, 0);
  }

  uint32_t codepoint = 0;
  uint32_t tmpbufi;
  uint8_t tmpbuf[4];
  static_assert(sizeof(tmpbufi) == sizeof(tmpbuf));

  for (int8_t i = 3; i >= 0; --i) {
    tmpbuf[i] = dcj_hextoi(*ctx->stri++);
  }

  memcpy(&tmpbufi, tmpbuf, sizeof(tmpbuf));
  if (tmpbufi & 0xf0f0f0f0) {
    dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_EXP_HEX, 0);
  }

  tmpbufi &= 0x0f0f0f0f;
  tmpbufi = (tmpbufi | tmpbufi >> 4) & 0x00ff00ff;
  codepoint = (tmpbufi | tmpbufi >> 8) & 0x0000ffff;

  if (codepoint >= 0xd800 && codepoint <= 0xdfff) {
    if (codepoint >= 0xdc00)
      dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_UEXP_HS, 0);
    codepoint &= 0x03ff;

    if (!dcj_parser_match(ctx, '\\') || !dcj_parser_match(ctx, 'u') ||
        dcj_buffer_remaining(ctx) < 3) {
      dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_EXP_CSP, 0);
    }

    for (int8_t i = 3; i >= 0; --i) {
      tmpbuf[i] = dcj_hextoi(*ctx->stri++);
    }

    memcpy(&tmpbufi, tmpbuf, sizeof(tmpbuf));
    if (tmpbufi & 0xf0f0f0f0) {
      dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_EXP_HEX, 0);
    }

    tmpbufi &= 0x0f0f0f0f;
    tmpbufi = (tmpbufi | tmpbufi >> 4) & 0x00ff00ff;
    tmpbufi = (tmpbufi | tmpbufi >> 8) & 0x0000ffff;

    if (tmpbufi < 0xdc00 || tmpbufi > 0xdfff) {
      dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_EXP_LSP, 0);
    }

    codepoint = (codepoint << 10) | tmpbufi;
    codepoint = codepoint + 0x10000;
  }

  if (codepoint < 0x0080) {
    buf[0] = codepoint;
    return 1;
  } else if (codepoint < 0x0800) {
    buf[0] = 0xc0 | (codepoint & 0x03c0) >> 6;
    buf[1] = 0x80 | (codepoint & 0x003f);
    return 2;
  } else if (codepoint < 0x10000) {
    buf[0] = 0xe0 | (codepoint & 0xf000) >> 12;
    buf[1] = 0x80 | (codepoint & 0x0fc0) >> 6;
    buf[2] = 0x80 | (codepoint & 0x003f);
    return 3;
  } else {
    buf[0] = 0xf0 | (codepoint & 0x1c0000) >> 18;
    buf[1] = 0x80 | (codepoint & 0x03f000) >> 12;
    buf[2] = 0x80 | (codepoint & 0x000fc0) >> 6;
    buf[3] = 0x80 | (codepoint & 0x00003f);
    return 4;
  }
}

mrb_value dcj_parse_string(mrb_state *mrb, struct dcj_parsing_ctx *ctx) {
  dcj_skip_whitespace(ctx);
  dcj_parser_expect(mrb, ctx, '"');

  const char *pbeg = ctx->stri;
  mrb_value str;

  /* this *should* be extracted to a match_string function... */
  _Bool is_reserved_key = dcj_parser_match(ctx, '@') && dcj_parser_match(ctx, '@') && dcj_parser_match(ctx, 'j') && dcj_parser_match(ctx, 'm') && dcj_parser_match(ctx, ':');
  if (is_reserved_key) { ctx->tosym = 1; }
  ctx->stri = pbeg;
  if ((ctx->opts->symbolize_keys && ctx->parsing_key) || ctx->tosym) {
    while (dcj_parser_match_fn(ctx, dcj_is_simplestring_c)) {
    }

    size_t len = ctx->stri - pbeg;
    if (dcj_parser_peek(ctx) == '"') {
      dcj_parser_adv(ctx);
      dcj_skip_whitespace(ctx);

      ctx->parsing_key = 0;
      ctx->tosym = 0;
      return mrb_symbol_value(mrb_intern(mrb, pbeg, len));
    }
    str = mrb_str_new(mrb, pbeg, len);
    goto fallback;
  }

  str = mrb_str_new_capa(mrb, 16);
  while (!(dcj_parser_match(ctx, '"') || dcj_past_end(ctx))) {
    pbeg = ctx->stri;
    while (dcj_parser_match_fn(ctx, dcj_is_simplestring_c)) {
    }
    
    size_t len = ctx->stri - pbeg;
    mrb_str_cat(mrb, str, pbeg, len);
  fallback:
    if (dcj_parser_peek(ctx) == '\\') {
      dcj_parser_adv(ctx);
      const char c = dcj_parser_peek(ctx);
      dcj_parser_adv(ctx);
      switch (c) {
      case '"':
      case '\\':
      case '/':
        mrb_str_cat(mrb, str, &c, 1);
        break;
      case 'b':
        mrb_str_cat_lit(mrb, str, "\b");
        break;
      case 'f':
        mrb_str_cat_lit(mrb, str, "\f");
        break;
      case 'n':
        mrb_str_cat_lit(mrb, str, "\n");
        break;
      case 'r':
        mrb_str_cat_lit(mrb, str, "\r");
        break;
      case 't':
        mrb_str_cat_lit(mrb, str, "\t");
        break;
      case 'u':
        char buf[4] = {};
        size_t seqlen = dcj_parse_hex_esc(mrb, ctx, buf);
        mrb_str_cat(mrb, str, buf, seqlen);
        break;
      default:
        dcj_notimpl(mrb, mrb->c->ci[0].stack[1]);
      }
    }
  }

  if ((ctx->opts->symbolize_keys && ctx->parsing_key) || ctx->tosym) {
    ctx->parsing_key = 0;
    ctx->tosym = 0;
    str = mrb_symbol_value(mrb_intern_str(mrb, str));
  }
  return str;
}

mrb_value dcj_parse_key(mrb_state *mrb, struct dcj_parsing_ctx *ctx) {
  ctx->parsing_key = 1;
  return dcj_parse_string(mrb, ctx);
}

// inexact - slow - etc.
mrb_value dcj_parse_number(mrb_state *mrb, struct dcj_parsing_ctx *ctx) {
  int8_t sign = 1;
  if (dcj_parser_match(ctx, '-'))
    sign = -1;

  const char *int_end = ctx->stri;
  double value = 0.0;

  if (dcj_parser_match(ctx, '0')) {
    int_end = ctx->stri;
    if (dcj_parser_match(ctx, '.'))
      goto l_float;
    else if (dcj_parser_match(ctx, 'e') || dcj_parser_match(ctx, 'E'))
      goto l_exp;
    else if (ctx->opts->int_lit_int)
      return mrb_int_value(mrb, 0);
    else
      return mrb_float_value(mrb, 0.0);
  }

  while (dcj_parser_match_noadv_fn(ctx, dcj_is_digit)) {
    value = value * 10.0 + ((*ctx->stri) - '0');
    dcj_parser_adv(ctx);
  }

  if (ctx->stri == int_end)
    dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_EXP_NUM, 0);

  int_end = ctx->stri;

  double divisor = 0.1;
  if (dcj_parser_match(ctx, '.')) {
  l_float:
    if (!dcj_parser_match_noadv_fn(ctx, dcj_is_digit)) {
      dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_EXP_NUM, 0);
    }

    while (dcj_parser_match_noadv_fn(ctx, dcj_is_digit)) {
      value += ((*ctx->stri) - '0') * divisor;
      divisor /= 10;
      dcj_parser_adv(ctx);
    }
  }

  if (dcj_parser_match(ctx, 'e') || dcj_parser_match(ctx, 'E')) {
  l_exp:
    int8_t expsgn = 1;
    mrb_int exponent = 0;

    if (dcj_parser_match(ctx, '-'))
      expsgn = -1;
    if (!dcj_parser_match_noadv_fn(ctx, dcj_is_digit)) {
      dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_EXP_NUM, 0);
    }

    while (dcj_parser_match_noadv_fn(ctx, dcj_is_digit)) {
      exponent = exponent * 10 + ((*ctx->stri) - '0');
      dcj_parser_adv(ctx);
    }
    value *= exp10(exponent * expsgn);
  }

  if (ctx->opts->int_lit_int && ctx->stri == int_end) {
    return mrb_int_value(mrb, (mrb_int)value * sign);
  } else {
    return mrb_float_value(mrb, value * sign);
  }
}

mrb_value dcj_parse_object(mrb_state *mrb, struct dcj_parsing_ctx *ctx) {
  dcj_parser_expect(mrb, ctx, '{');
  dcj_skip_whitespace(ctx);
  if (dcj_parser_match(ctx, '}')) {
    return mrb_hash_new(mrb);
  }

  /* all this just to find special cases :< */
  mrb_value hash = mrb_nil_value();
  mrb_value key = dcj_parse_key(mrb, ctx);
  dcj_skip_whitespace(ctx);
  dcj_parser_expect(mrb, ctx, ':');
  dcj_skip_whitespace(ctx);
  if (mrb_obj_equal(mrb, key, usymv(jsonmarker_symbol)) && ctx->opts->sym_ext) {
    ctx->tosym = 1;
    mrb_value v = dcj_parse_string(mrb, ctx);
    dcj_skip_whitespace(ctx);
    dcj_parser_expect(mrb, ctx, '}');
    return v;
  }

  mrb_value val = dcj_parse_value(mrb, ctx);
  dcj_skip_whitespace(ctx);

  hash = mrb_hash_new(mrb);
  mrb_hash_set(mrb, hash, key, val);

  while (dcj_parser_match(ctx, ',')) {
    dcj_skip_whitespace(ctx);
    key = dcj_parse_key(mrb, ctx);
    dcj_skip_whitespace(ctx);
    dcj_parser_expect(mrb, ctx, ':');

    val = dcj_parse_value(mrb, ctx);
    dcj_skip_whitespace(ctx);

    mrb_hash_set(mrb, hash, key, val);
  }

  /* dcj_skip_whitespace(ctx); */
  dcj_parser_expect(mrb, ctx, '}');
  return hash;
}

mrb_value dcj_parse_array(mrb_state *mrb, struct dcj_parsing_ctx *ctx) {
  dcj_parser_expect(mrb, ctx, '[');
  dcj_skip_whitespace(ctx);
  if (dcj_parser_match(ctx, ']')) {
    return mrb_ary_new(mrb);
  }

  mrb_value ary = mrb_ary_new(mrb);

  do {
    mrb_value elem = dcj_parse_value(mrb, ctx);
    mrb_ary_push(mrb, ary, elem);
    dcj_skip_whitespace(ctx);
  } while (dcj_parser_match(ctx, ','));

  dcj_parser_expect(mrb, ctx, ']');
  return ary;
}

mrb_value dcj_parse_value(mrb_state *mrb, struct dcj_parsing_ctx *ctx) {
  dcj_skip_whitespace(ctx);
  if (dcj_past_end(ctx))
    dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_UEXP_EOF, 0);

  switch (dcj_parser_peek(ctx)) {
  case 0:
    dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_UEXP_EOF, 0);
  case '-':
  case '0' ... '9':
    return dcj_parse_number(mrb, ctx);
  case '"':
    return dcj_parse_string(mrb, ctx);
  case '[':
    return dcj_parse_array(mrb, ctx);
  case '{':
    return dcj_parse_object(mrb, ctx);
  case 't':
    if (dcj_buffer_remaining(ctx) < 4) {
      dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_UEXP_EOF, 0);
    }

    MAP(dcj_parser_expect, mrb, ctx, 't', 'r', 'u', 'e');

    return mrb_true_value();
  case 'f':
    if (dcj_buffer_remaining(ctx) < 4) {
      dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_UEXP_EOF, 0);
    }

    MAP(dcj_parser_expect, mrb, ctx, 'f', 'a', 'l', 's', 'e');

    return mrb_false_value();
  case 'n':
    if (dcj_buffer_remaining(ctx) < 4) {
      dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_UEXP_EOF, 0);
    }

    MAP(dcj_parser_expect, mrb, ctx, 'n', 'u', 'l', 'l');

    return mrb_nil_value();
  default:
    dcj_parser_raise_unexpected(mrb, ctx, DCJ_UT_EXP_VAL, dcj_parser_peek(ctx));
    __builtin_unreachable();
  }
}

mrb_value dcj_parse_json_m(mrb_state *mrb, mrb_value) {
  mrb_value rstr;
  const struct json_opts_t *opts;
  mrb_int argc = mrb_get_args(mrb, "S|I!", &rstr, &opts, json_opts_class);
  mrb_gc_protect(mrb, rstr);
  const char *str = RSTRING_PTR(rstr);
  mrb_int len = RSTRING_LEN(rstr);

  if (argc < 2) {
    opts = &default_opts;
  }

  struct dcj_parsing_ctx ctx = {.str = str,
                                .stri = str,
                                .send = str + len,
                                .obeg = nullptr,
                                .co = mrb_nil_value(),
                                .opts = opts,
                                .parsing_key = 0};

  dcj_skip_whitespace(&ctx);
  if (!ctx.opts->slurp) {
    mrb_value ret = dcj_parse_value(mrb, &ctx);
    dcj_skip_whitespace(&ctx);
    if (!dcj_past_end(&ctx)) {
      dcj_parser_raise_unexpected(mrb, &ctx, DCJ_UT_EXP_EOF, 0);
    }
    return ret;
  } else {
    mrb_value ary = mrb_ary_new(mrb);
    if (dcj_past_end(&ctx)) {
      return ary;
    }

    while (!dcj_past_end(&ctx)) {
      mrb_ary_push(mrb, ary, dcj_parse_value(mrb, &ctx));
    }

    return ary;
  }
}

void drb_register_c_extensions_with_api(mrb_state *mrb, struct drb_api_t *) {
#define hexlutsetup(beg, end, off)                                             \
  do {                                                                         \
    static_assert(beg <= end);                                                 \
    for (uint8_t i = beg; i <= end; ++i) {                                     \
      hexlut[i] = i + off;                                                     \
    }                                                                          \
  } while (0)

  hexlutsetup('0', '9', -'0');
  hexlutsetup('a', 'f', -'a' + 10);
  hexlutsetup('A', 'F', -'A' + 10);

#define SFUNC(name, def) init_usym2(mrb, name, def);
#include "symbols.inc"
#undef SFUNC

  struct RClass *argonaut_mod = mrb_define_module_id(mrb, usym(Argonaut));
  struct RClass *json_mod =
      mrb_define_module_under_id(mrb, argonaut_mod, usym(JSON));

  parse_error_class = mrb_define_class_under_id(
      mrb, json_mod, usym(ParseError),
      mrb_exc_get_id(mrb, mrb_intern_lit(mrb, "StandardError")));

  json_opts_class = mrb_define_class_under_id(mrb, json_mod, usym(Options),
                                              mrb->object_class);
  MRB_SET_INSTANCE_TT(json_opts_class, MRB_TT_ISTRUCT);
  mrb_value json_opts_class_v = mrb_obj_value(json_opts_class);

  default_opts_val = dcj_json_opts_newc(mrb, default_opts);
  MRB_SET_FROZEN_FLAG(mrb_obj_ptr(default_opts_val));
  minify_opts_val = dcj_json_opts_newc(mrb, minify_opts);
  MRB_SET_FROZEN_FLAG(mrb_obj_ptr(minify_opts_val));

  mrb_define_class_method_id(mrb, json_opts_class, usym(new),
                             dcj_json_opts_new_m, MRB_ARGS_KEY(0, 8));
  mrb_define_module_function_id(mrb, json_opts_class, usym(default),
                                dcj_json_opts_default, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, json_opts_class, usym(minified),
                                dcj_json_opts_minify, MRB_ARGS_NONE());
  mrb_const_set(mrb, json_opts_class_v, usym(DEFAULT), default_opts_val);
  mrb_const_set(mrb, json_opts_class_v, usym(MINIFIED), minify_opts_val);
  mrb_define_method_id(mrb, json_opts_class, usym(inspect),
                       dcj_json_opts_inspect, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, json_opts_class, usym(to_s), dcj_json_opts_inspect,
                       MRB_ARGS_NONE());

  mrb_define_method_id(mrb, mrb->string_class, usym(to_json), dcj_notimpl,
                       MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, mrb->array_class, usym(to_json), dcj_notimpl,
                       MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, mrb->hash_class, usym(to_json), dcj_notimpl,
                       MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, mrb->integer_class, usym(to_json), dcj_notimpl,
                       MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, mrb->float_class, usym(to_json), dcj_notimpl,
                       MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, mrb->true_class, usym(to_json), dcj_notimpl,
                       MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, mrb->false_class, usym(to_json), dcj_notimpl,
                       MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, mrb->nil_class, usym(to_json), dcj_notimpl,
                       MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, mrb->symbol_class, usym(to_json), dcj_notimpl,
                       MRB_ARGS_OPT(1));

  mrb_define_module_function_id(mrb, json_mod, usym(parse), dcj_parse_json_m,
                                MRB_ARGS_REQ(1));
}
