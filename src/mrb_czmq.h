#ifndef MRB_CZMQ_H
#define MRB_CZMQ_H

#include <mruby.h>
#include <mruby/throw.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/value.h>
#include <czmq.h>
#include <mruby/data.h>
#include <mruby/class.h>
#include <mruby/variable.h>
#include <mruby/hash.h>
#include <mruby/array.h>
#include <mruby/string.h>
#include <mruby/error.h>
#include <errno.h>

static void
mrb_zsock_actor_destroy(mrb_state *mrb, void *p)
{
  if (p) {
    if (zsock_is(p))
      zsock_destroy((zsock_t **) &p);
    else
    if (zactor_is(p))
      zactor_destroy((zactor_t **) &p);
  }
}

static const struct mrb_data_type mrb_zsock_actor_type = {
  "$i_mrb_zsock_actor_type", mrb_zsock_actor_destroy
};

static void
mrb_zframe_destroy(mrb_state *mrb, void *p)
{
  zframe_destroy((zframe_t **) &p);
}

static const struct mrb_data_type mrb_zframe_type = {
  "$i_mrb_zframe_type", mrb_zframe_destroy
};

static void
mrb_zconfig_destroy(mrb_state *mrb, void *p)
{
  zconfig_destroy((zconfig_t **) &p);
}

static const struct mrb_data_type mrb_zconfig_type = {
  "$i_mrb_zconfig_type", mrb_zconfig_destroy
};

static const struct mrb_data_type mrb_pollitem_type = {
  "$i_mrb_pollitem_type", mrb_free
};

#endif
