#include "dragonruby.h"
#include "mruby.h"
#include "mruby/istruct.h"
#include <stdint.h>

#define usym(name) usym__##name
#define usymv(name) usym(val__##name)
#define declare_usym(name)                                                     \
  mrb_sym usym(name);                                                          \
  mrb_value usymv(name)
#define init_usym2(mrb, declname, symname)                                     \
  usym(declname) = mrb_intern_lit(mrb, symname);                               \
  usymv(declname) = mrb_symbol_value(usym(declname))
#define init_usym(mrb, name) init_usym2(mrb, name, #name)

declare_usym(Argonaut);
declare_usym(JSON);
declare_usym(JSONOptions);
declare_usym(DEFAULT);
declare_usym(default);
declare_usym(MINIFIED);
declare_usym(minified);
declare_usym(to_json);
declare_usym(parse);
declare_usym(inspect);
declare_usym(to_s);

struct json_opts_t {
  uint8_t indent_width;
  uint8_t indent_depth;
  struct {
    uint8_t sym_ext : 1;
    uint8_t obj_ext : 1;
    uint8_t spc_nul : 1;
    uint8_t minify : 1;
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
                                   .sym_ext = 0,
                                   .obj_ext = 0,
                                   .spc_nul = 0,
                                   .minify = 0};
mrb_value default_opts_val;

struct json_opts_t minify_opts = {.indent_width = 0,
                                  .indent_depth = 0,
                                  .sym_ext = 0,
                                  .obj_ext = 0,
                                  .spc_nul = 0,
                                  .minify = 1};
mrb_value minify_opts_val;

struct RClass *json_opts_class;

#define DCJ_MAX_NESTING 256

struct dcj_parsing_ctx {
  uint32_t sp;
  mrb_value stack[DCJ_MAX_NESTING];
};

mrb_value dcj_json_opts_newc(mrb_state *mrb, struct json_opts_t opts) {
  mrb_value instance;
  alloc_init_json_opts_val(mrb, instance, opts);
  return instance;
}

mrb_value dcj_json_opts_new_m(mrb_state *mrb, mrb_value) {
  return dcj_json_opts_newc(mrb, default_opts);
}

mrb_value dcj_json_opts_inspect(mrb_state *mrb, mrb_value self) {
  struct json_opts_t opts = *unwrap_istruct_json_opts(self);
  mrb_value rbool[2] = {mrb_false_value(), mrb_true_value()};
  return mrb_format(mrb,
                    "%T { indent_width: %i, symbol_ext: %v, object_ext: %v, "
                    "space_in_empty: %v, minify: %v}",
                    self, (mrb_int)opts.indent_width, rbool[opts.sym_ext],
                    rbool[opts.obj_ext], rbool[opts.spc_nul],
                    rbool[opts.minify]);
}

mrb_value dcj_json_opts_default(mrb_state *, mrb_value) {
  return default_opts_val;
}

mrb_value dcj_json_opts_minify(mrb_state *, mrb_value) {
  return minify_opts_val;
}

mrb_value dcj_notimpl(mrb_state *mrb, mrb_value self) {
  mrb_sym mid = mrb->c->ci->mid;

  if (mrb_class_p(self) || mrb_module_p(self)) {
    mrb_raisef(mrb, E_NOTIMP_ERROR, "%C.%n is not yet implemented",
               mrb_class_ptr(self), mid);
  } else if (mrb_sclass_p(self)) {
    mrb_raisef(mrb, E_NOTIMP_ERROR, "%C#%n is not yet implemented",
               mrb_class_ptr(self), mid);
  } else {
    mrb_raisef(mrb, E_NOTIMP_ERROR, "%Y#%n is not yet implemented", self, mid);
  }
}

mrb_value dcj_parse_json_top(mrb_state *mrb, mrb_value) {
  struct dcj_parsing_ctx ctx = {0};
  const char *str;
  const char *l_start;
  mrb_int len = 0;
  char c = 0;
  const struct json_opts_t *opts;
  mrb_int argc = mrb_get_args(mrb, "s|I!", &str, &len, &opts, json_opts_class);
  const char *const send = str + len;

  if (argc < 2) {
    opts = &default_opts;
  }

  mrb_value self = mrb_nil_value();
  // glorified while loop
top:
  l_start = str;
  if (str >= send) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "bad parse (oob)");
  }
  switch (c = *str++) {
  case ' ':
  case '\t':
  case '\n':
  case '\r':
    goto top;
  case '-':
  case '0' ... '9':
    // number
    char *flt_end;
    mrb_float val = mrb_float_read(l_start, &flt_end);
    str = flt_end;
    self = mrb_float_value(mrb, val);
    goto pushv;
  case '"':
    // string
    self = mrb_undef_value();

    l_start = str;
    c = *str;

    while (c != '"') {
      
    }

    if (mrb_undef_p(self)) {
      self = mrb_str_new_lit(mrb, "");
    }
    
    goto pushv;
  case '[':
    // array
    ctx.stack[ctx.sp++] = mrb_ary_new(mrb);
    goto top;
  case ']':
    if (!mrb_array_p(ctx.stack[ctx.sp - 1])) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "bad parse (ctx mismatch)");
    } else {
      self = ctx.stack[--ctx.sp];
      goto pushv;
    }
  default:
    mrb_raisef(mrb, E_RUNTIME_ERROR, "unexpected char %c [%i]", c, (mrb_int)c);
    break;
  pushv:
    if (ctx.sp == 0)
      goto done;

    if (mrb_array_p(ctx.stack[ctx.sp])) {
      mrb_ary_push(mrb, ctx.stack[ctx.sp], self);
    } else if (mrb_hash_p(ctx.stack[ctx.sp - 1])) {
      mrb_hash_set(mrb, ctx.stack[ctx.sp - 1], ctx.stack[ctx.sp], self);
      --ctx.sp;
    } else {
      mrb_raise(mrb, E_RUNTIME_ERROR, "bad parse (error)");
    }
  }

done:
  return self;
}

void drb_register_c_extensions_with_api(mrb_state *mrb, struct drb_api_t *) {
  init_usym(mrb, Argonaut);
  init_usym(mrb, JSON);
  init_usym(mrb, JSONOptions);
  init_usym(mrb, DEFAULT);
  init_usym(mrb, default);
  init_usym(mrb, MINIFIED);
  init_usym(mrb, minified);
  init_usym(mrb, to_json);
  init_usym(mrb, parse);
  init_usym(mrb, inspect);
  init_usym(mrb, to_s);

  struct RClass *argonaut_mod = mrb_define_module_id(mrb, usym(Argonaut));
  struct RClass *json_mod =
      mrb_define_module_under_id(mrb, argonaut_mod, usym(JSON));
  json_opts_class = mrb_define_class_under_id(
      mrb, argonaut_mod, usym(JSONOptions), mrb->object_class);
  MRB_SET_INSTANCE_TT(json_opts_class, MRB_TT_ISTRUCT);
  mrb_value json_opts_class_v = mrb_obj_value(json_opts_class);

  default_opts_val = dcj_json_opts_newc(mrb, default_opts);
  MRB_SET_FROZEN_FLAG(mrb_obj_ptr(default_opts_val));
  minify_opts_val = dcj_json_opts_newc(mrb, minify_opts);
  MRB_SET_FROZEN_FLAG(mrb_obj_ptr(minify_opts_val));

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

  mrb_define_module_function_id(mrb, json_mod, usym(parse), dcj_parse_json_top,
                                MRB_ARGS_REQ(1));
}
