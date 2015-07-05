#ifndef MRUBY_CZMQ_H
#define MRUBY_CZMQ_H

#include <mruby.h>

#ifdef __cplusplus
extern "C" {
#endif

#define E_CZMQ_ERROR mrb_class_get_under(mrb, mrb_module_get(mrb, "CZMQ"), "Error")

#ifdef __cplusplus
}
#endif

#endif
