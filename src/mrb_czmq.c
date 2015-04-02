#include "mruby/czmq.h"
#include "mrb_czmq.h"

static mrb_value
mrb_zsys_error(mrb_state *mrb, mrb_value self)
{
  char *msg;

  mrb_get_args(mrb, "z", &msg);

  zsys_error("%s", msg);

  return self;
}

static mrb_value
mrb_zsys_warning(mrb_state *mrb, mrb_value self)
{
  char *msg;

  mrb_get_args(mrb, "z", &msg);

  zsys_warning("%s", msg);

  return self;
}

static mrb_value
mrb_zsys_notice(mrb_state *mrb, mrb_value self)
{
  char *msg;

  mrb_get_args(mrb, "z", &msg);

  zsys_notice("%s", msg);

  return self;
}

static mrb_value
mrb_zsys_info(mrb_state *mrb, mrb_value self)
{
  char *msg;

  mrb_get_args(mrb, "z", &msg);

  zsys_info("%s", msg);

  return self;
}

static mrb_value
mrb_zsys_debug(mrb_state *mrb, mrb_value self)
{
  char *msg;

  mrb_get_args(mrb, "z", &msg);

  zsys_debug("%s", msg);

  return self;
}

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

static mrb_value
mrb_zsock_initialize(mrb_state *mrb, mrb_value self)
{
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "readers"), mrb_ary_new(mrb));

  return self;
}

static mrb_value
mrb_zsock_new_stream(mrb_state *mrb, mrb_value self)
{
  char* endpoint;

  mrb_get_args(mrb, "z", &endpoint);

  zsock_t *zsock = zsock_new_stream(endpoint);
  if (zsock) {
    mrb_value zsock_actor_obj = mrb_obj_new(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), 0, NULL);

    mrb_data_init(zsock_actor_obj, zsock, &mrb_zsock_actor_type);

    return zsock_actor_obj;
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zsock_signal(mrb_state *mrb, mrb_value self)
{
  mrb_int status = 0;

  mrb_get_args(mrb, "|i", &status);

  if (status < 0 ||status > UCHAR_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "status is out of range");

  if (zsock_signal(DATA_PTR(self), (byte) status) == 0)
    return self;
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zsock_wait(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(zsock_wait(DATA_PTR(self)));
}

static void
mrb_zloop_destroy(mrb_state *mrb, void *p)
{
  zloop_destroy((zloop_t **) &p);
}

static const struct mrb_data_type mrb_zloop_type = {
  "$i_mrb_zloop_type", mrb_zloop_destroy
};

static mrb_value
mrb_zloop_new(mrb_state *mrb, mrb_value self)
{
  zloop_t *zloop = zloop_new();
  if (zloop) {
    mrb_data_init(self, zloop, &mrb_zloop_type);

    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "timers"), mrb_hash_new(mrb));
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "tickets"), mrb_hash_new(mrb));

    return self;
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

typedef struct {
  mrb_state *mrb;
  mrb_value handler;
  mrb_value extra;
} mrb_zloop_arg_t;

static const struct mrb_data_type mrb_czmq_callback_arg_type = {
  "$i_mrb_czmq_callback_arg_type", mrb_free
};

static int
mrb_zloop_timer_fn(zloop_t *zloop, int timer_id, void *arg)
{
  mrb_zloop_arg_t *zloop_arg = (mrb_zloop_arg_t *) arg;
  mrb_state *mrb = zloop_arg->mrb;

  int ai = mrb_gc_arena_save(mrb);

  int rc = mrb_int(mrb, mrb_yield(mrb, zloop_arg->handler,
    zloop_arg->extra));

  mrb_gc_arena_restore(mrb, ai);

  return rc;
}

static mrb_value
mrb_zloop_timer(mrb_state *mrb, mrb_value self)
{
  mrb_int delay, times;
  mrb_value handler;

  mrb_get_args(mrb, "ii&", &delay, &times, &handler);

  if (delay < 0 ||times < 0)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "delay and times mustn't be negative");

  mrb_zloop_arg_t *zloop_arg = (mrb_zloop_arg_t *) mrb_calloc(mrb, 1,
    sizeof(mrb_zloop_arg_t));
  zloop_arg->mrb = mrb;
  zloop_arg->handler = handler;

  int timer_id = zloop_timer((zloop_t *) DATA_PTR(self), delay, times,
    mrb_zloop_timer_fn, zloop_arg);

  if (timer_id != -1) {
    mrb_value callback = mrb_obj_value(mrb_data_object_alloc(mrb,
      mrb_class_get_under(mrb, mrb_module_get(mrb, "CZMQ"), "Callback"),
      zloop_arg, &mrb_czmq_callback_arg_type));
    zloop_arg->extra = mrb_fixnum_value(timer_id);
    mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "timers")),
      zloop_arg->extra, callback);

    return zloop_arg->extra;
  }
  else {
    mrb_free(mrb, zloop_arg);
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
  }
}

static mrb_value
mrb_zloop_timer_end(mrb_state *mrb, mrb_value self)
{
  mrb_int timer_id;

  mrb_get_args(mrb, "i", &timer_id);

  if (timer_id < 0 ||timer_id > INT_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "timer_id is out of range");

  if (!mrb_nil_p(mrb_hash_delete_key(mrb, mrb_iv_get(mrb, self,
    mrb_intern_lit(mrb, "timers")), mrb_fixnum_value(timer_id)))) {
    zloop_timer_end((zloop_t *) DATA_PTR(self), timer_id);
    return self;
  }
  else
    return mrb_nil_value();
}

static mrb_value
mrb_zloop_ticket(mrb_state *mrb, mrb_value self)
{
  mrb_value handler;

  mrb_get_args(mrb, "&", &handler);

  mrb_zloop_arg_t *zloop_arg = (mrb_zloop_arg_t *) mrb_calloc(mrb, 1,
    sizeof(mrb_zloop_arg_t));
  zloop_arg->mrb = mrb;
  zloop_arg->handler = handler;

  void *handle = zloop_ticket((zloop_t *) DATA_PTR(self),
    mrb_zloop_timer_fn, zloop_arg);

  if (handle) {
    mrb_value callback = mrb_obj_value(mrb_data_object_alloc(mrb,
      mrb_class_get_under(mrb, mrb_module_get(mrb, "CZMQ"), "Callback"),
      zloop_arg, &mrb_czmq_callback_arg_type));

    zloop_arg->extra = mrb_cptr_value(mrb, handle);

    mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "tickets")),
      zloop_arg->extra, callback);

    return zloop_arg->extra;
  }
  else {
    mrb_free(mrb, zloop_arg);
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
  }
}

static mrb_value
mrb_zloop_ticket_reset(mrb_state *mrb, mrb_value self)
{
  mrb_value handle_obj;

  mrb_get_args(mrb, "o", &handle_obj);

  if (!mrb_cptr_p(handle_obj))
    mrb_raise(mrb, E_TYPE_ERROR, "handle is not a c pointer");

  if (!mrb_nil_p(mrb_hash_get(mrb, mrb_iv_get(mrb, self,
    mrb_intern_lit(mrb, "tickets")), handle_obj))) {
    zloop_ticket_reset((zloop_t *) DATA_PTR(self), mrb_cptr(handle_obj));
    return self;
  }
  else
    return mrb_nil_value();
}

static mrb_value
mrb_zloop_ticket_delete(mrb_state *mrb, mrb_value self)
{
  mrb_value handle_obj;

  mrb_get_args(mrb, "o", &handle_obj);
  if (!mrb_cptr_p(handle_obj))
    mrb_raise(mrb, E_TYPE_ERROR, "handle is not a c pointer");

  if (!mrb_nil_p(mrb_hash_delete_key(mrb, mrb_iv_get(mrb, self,
    mrb_intern_lit(mrb, "tickets")), handle_obj))) {
    zloop_ticket_delete((zloop_t *) DATA_PTR(self), mrb_cptr(handle_obj));
    return self;
  }
  else
    return mrb_nil_value();
}

static int
mrb_zloop_reader_fn(zloop_t *loop, zsock_t *reader, void *arg)
{
  mrb_zloop_arg_t *zloop_arg = (mrb_zloop_arg_t *) arg;
  mrb_state *mrb = zloop_arg->mrb;

  int ai = mrb_gc_arena_save(mrb);

  int rc = mrb_int(mrb, mrb_yield(mrb, zloop_arg->handler,
    zloop_arg->extra));

  mrb_gc_arena_restore(mrb, ai);

  return rc;
}

static mrb_value
mrb_zloop_reader(mrb_state *mrb, mrb_value self)
{
  mrb_value zsock_actor_obj, handler;

  mrb_get_args(mrb, "o&", &zsock_actor_obj, &handler);
  void *zsock = mrb_data_check_get_ptr(mrb, zsock_actor_obj, &mrb_zsock_actor_type);

  mrb_zloop_arg_t *zloop_arg = (mrb_zloop_arg_t *) mrb_calloc(mrb, 1,
    sizeof(mrb_zloop_arg_t));
  zloop_arg->mrb = mrb;
  zloop_arg->handler = handler;
  zloop_arg->extra = zsock_actor_obj;

  if (zloop_reader((zloop_t *) DATA_PTR(self), zsock, mrb_zloop_reader_fn,
    zloop_arg) == 0) {
    mrb_value callback = mrb_obj_value(mrb_data_object_alloc(mrb,
      mrb_class_get_under(mrb, mrb_module_get(mrb, "CZMQ"), "Callback"),
      zloop_arg, &mrb_czmq_callback_arg_type));

    mrb_ary_push(mrb, mrb_iv_get(mrb, zsock_actor_obj,
      mrb_intern_lit(mrb, "readers")), callback);

    return self;
  }
  else {
    mrb_free(mrb, zloop_arg);
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
  }
}

static mrb_value
mrb_zloop_reader_end(mrb_state *mrb, mrb_value self)
{
  mrb_value zsock_actor_obj;

  mrb_get_args(mrb, "o", &zsock_actor_obj);

  void *zsock = mrb_data_check_get_ptr(mrb, zsock_actor_obj, &mrb_zsock_actor_type);

  mrb_ary_clear(mrb, mrb_iv_get(mrb, zsock_actor_obj,
      mrb_intern_lit(mrb, "readers")));
  zloop_reader_end((zloop_t *) DATA_PTR(self), zsock);

  return self;
}

static mrb_value
mrb_zloop_start(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(zloop_start((zloop_t *) DATA_PTR(self)));
}

static mrb_value
mrb_zloop_set_ticket_delay(mrb_state *mrb, mrb_value self)
{
  mrb_int delay;

  mrb_get_args(mrb, "i", &delay);

  if (delay < 0)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "delay mustn't be negative");

  zloop_set_ticket_delay((zloop_t *) DATA_PTR(self), delay);

  return self;
}

static mrb_value
mrb_zloop_set_verbose(mrb_state *mrb, mrb_value self)
{
  mrb_bool verbose;

  mrb_get_args(mrb, "b", &verbose);

  if (verbose == TRUE)
    zloop_set_verbose((zloop_t *) DATA_PTR(self), true);
  else
    zloop_set_verbose((zloop_t *) DATA_PTR(self), false);

  return self;
}

static void
mrb_zframe_destroy(mrb_state *mrb, void *p)
{
  zframe_destroy((zframe_t **) &p);
}

static const struct mrb_data_type mrb_zframe_type = {
  "$i_mrb_zframe_type", mrb_zframe_destroy
};

static mrb_value
mrb_zframe_new(mrb_state *mrb, mrb_value self)
{
  char* data = NULL;
  mrb_int size = 0;

  mrb_get_args(mrb, "|s", &data, &size);

  zframe_t *zframe = zframe_new(data, size);
  if (zframe) {
    mrb_data_init(self, zframe, &mrb_zframe_type);

    return self;
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zframe_recv(mrb_state *mrb, mrb_value self)
{
  void *zsock_actor;

  mrb_get_args(mrb, "d", &zsock_actor, &mrb_zsock_actor_type);

  zframe_t *zframe = zframe_recv(zsock_actor);
  if (zframe)
    return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zframe"), zframe, &mrb_zframe_type));
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zframe_data(mrb_state *mrb, mrb_value self)
{
  return mrb_cptr_value(mrb, zframe_data((zframe_t *) DATA_PTR(self)));
}

static mrb_value
mrb_zframe_size(mrb_state *mrb, mrb_value self)
{
  size_t size = zframe_size((zframe_t *) DATA_PTR(self));
  if (size > MRB_INT_MAX)
    return mrb_float_value(mrb, size);
  else
    return mrb_fixnum_value(size);
}

static mrb_value
mrb_zframe_to_str(mrb_state *mrb, mrb_value self)
{
  zframe_t *zframe = (zframe_t *) DATA_PTR(self);

  return mrb_str_new_static(mrb, (const char *) zframe_data(zframe), zframe_size(zframe));
}

static mrb_value
mrb_zframe_reset(mrb_state *mrb, mrb_value self)
{
  char *data;
  mrb_int size;

  mrb_get_args(mrb, "s", &data, &size);

  zframe_reset((zframe_t *) DATA_PTR(self), data, size);

  return self;
}

static mrb_value
mrb_zframe_send(mrb_state *mrb, mrb_value self)
{
  void *zsock_actor;
  mrb_int flags = 0;

  mrb_get_args(mrb, "d|i", &zsock_actor, &mrb_zsock_actor_type, &flags);

  if (zframe_send((zframe_t **) &DATA_PTR(self), zsock_actor, flags) == 0)
    return mrb_true_value();
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zframe_more(mrb_state *mrb, mrb_value self)
{
  if (zframe_more((zframe_t *) DATA_PTR(self)) == 1)
    return mrb_true_value();
  else
    return mrb_false_value();
}

static mrb_value
mrb_zactor_new_zauth(mrb_state *mrb, mrb_value self)
{
  zactor_t *zactor = zactor_new(zauth, NULL);
  if (zactor) {
    mrb_value zsock_actor_obj = mrb_obj_new(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), 0, NULL);

    mrb_data_init(zsock_actor_obj, zactor, &mrb_zsock_actor_type);

    return zsock_actor_obj;
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zactor_new_zbeacon(mrb_state *mrb, mrb_value self)
{
  zactor_t *zactor = zactor_new(zbeacon, NULL);
  if (zactor) {
    mrb_value zsock_actor_obj = mrb_obj_new(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), 0, NULL);

    mrb_data_init(zsock_actor_obj, zactor, &mrb_zsock_actor_type);

    return zsock_actor_obj;
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zactor_new_zgossip(mrb_state *mrb, mrb_value self)
{
  char *prefix;

  mrb_get_args(mrb, "z", &prefix);

  zactor_t *zactor = zactor_new(zgossip, prefix);
  if (zactor) {
    mrb_value zsock_actor_obj = mrb_obj_new(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), 0, NULL);

    mrb_data_init(zsock_actor_obj, zactor, &mrb_zsock_actor_type);

    return zsock_actor_obj;
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zactor_new_zmonitor(mrb_state *mrb, mrb_value self)
{
  void *socket;

  mrb_get_args(mrb, "d", &socket, &mrb_zsock_actor_type);

  zactor_t *zactor = zactor_new(zmonitor, socket);
  if (zactor) {
    mrb_value zsock_actor_obj = mrb_obj_new(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), 0, NULL);

    mrb_data_init(zsock_actor_obj, zactor, &mrb_zsock_actor_type);

    return zsock_actor_obj;
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zactor_new_zproxy(mrb_state *mrb, mrb_value self)
{
  zactor_t *zactor = zactor_new(zproxy, NULL);
  if (zactor) {
    mrb_value zsock_actor_obj = mrb_obj_new(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), 0, NULL);

    mrb_data_init(zsock_actor_obj, zactor, &mrb_zsock_actor_type);

    return zsock_actor_obj;
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static void
mrb_zconfig_destroy(mrb_state *mrb, void *p)
{
  zconfig_destroy((zconfig_t **) &p);
}

static const struct mrb_data_type mrb_zconfig_type = {
  "$i_mrb_zconfig_type", mrb_zconfig_destroy
};

static mrb_value
mrb_zconfig_new(mrb_state *mrb, mrb_value self)
{
  char *name;
  zconfig_t *parent = NULL, *config;

  mrb_get_args(mrb, "z|d", &name, &parent, &mrb_zconfig_type);

  config = zconfig_new (name, parent);
  if (config)
    mrb_data_init(self, config, &mrb_zconfig_type);
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));

  return self;
}

static mrb_value
mrb_zconfig_name(mrb_state *mrb, mrb_value self)
{
  char *name = zconfig_name((zconfig_t *) DATA_PTR(self));

  if (name)
    return mrb_str_new_static(mrb, name, strlen(name));
  else
    return mrb_nil_value();
}

static mrb_value
mrb_zconfig_value(mrb_state *mrb, mrb_value self)
{
  char *value = zconfig_value((zconfig_t *) DATA_PTR(self));

  if (value)
    return mrb_str_new_static(mrb, value, strlen(value));
  else
    return mrb_nil_value();
}

static mrb_value
mrb_zconfig_put(mrb_state *mrb, mrb_value self)
{
  char *path, *value;

  mrb_get_args(mrb, "zz", &path, &value);

  zconfig_put((zconfig_t *) DATA_PTR(self), path, value);

  return self;
}

static mrb_value
mrb_zconfig_set_name(mrb_state *mrb, mrb_value self)
{
  char *name;

  mrb_get_args(mrb, "z", &name);

  zconfig_set_name((zconfig_t *) DATA_PTR(self), name);

  return self;
}

static mrb_value
mrb_zconfig_set_value(mrb_state *mrb, mrb_value self)
{
  char *value;

  mrb_get_args(mrb, "z", &value);

  zconfig_set_value((zconfig_t *) DATA_PTR(self), "%s", value);

  return self;
}

static mrb_value
mrb_zconfig_resolve(mrb_state *mrb, mrb_value self)
{
  char *path, *default_value = NULL, *value;

  mrb_get_args(mrb, "z|z", &path, &default_value);

  value = zconfig_resolve((zconfig_t *) DATA_PTR(self), path, default_value);

  if (value)
    return mrb_str_new_static(mrb, value, strlen(value));
  else
    return mrb_nil_value();
}

static mrb_value
mrb_zconfig_load(mrb_state *mrb, mrb_value self)
{
  char *filename;

  mrb_get_args(mrb, "z", &filename);

  zconfig_t *zconfig = zconfig_load(filename);

  if (zconfig)
    return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zconfig"), zconfig, &mrb_zconfig_type));
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zconfig_save(mrb_state *mrb, mrb_value self)
{
  char *filename;

  mrb_get_args(mrb, "z", &filename);

  if (zconfig_save((zconfig_t *) DATA_PTR(self), filename) == 0)
    return self;
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zconfig_filename(mrb_state *mrb, mrb_value self)
{
  const char *filename = zconfig_filename((zconfig_t *) DATA_PTR(self));

  if (filename)
    return mrb_str_new_static(mrb, filename, strlen(filename));
  else
    return mrb_nil_value();
}

static mrb_value
mrb_zconfig_reload(mrb_state *mrb, mrb_value self)
{
  if (zconfig_reload((zconfig_t **) &DATA_PTR(self)) == 0)
    return self;
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zconfig_has_changed(mrb_state *mrb, mrb_value self)
{
  if (zconfig_has_changed((zconfig_t *) DATA_PTR(self)) == true)
    return mrb_true_value();
  else
    return mrb_false_value();
}

void
mrb_mruby_czmq_gem_init(mrb_state* mrb) {
  struct RClass *czmq_mod, *zsys_mod, *zsock_class,
  *callback_class, *zloop_class, *zframe_class, *zactor_class, *zconfig_class;

  czmq_mod = mrb_define_module(mrb, "CZMQ");
  mrb_define_class_under(mrb, czmq_mod, "Error", E_RUNTIME_ERROR);

  zsys_mod = mrb_define_module_under(mrb, czmq_mod, "Zsys");
  mrb_define_module_function(mrb, zsys_mod, "error",   mrb_zsys_error,    MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zsys_mod, "warning", mrb_zsys_warning,  MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zsys_mod, "notice",  mrb_zsys_notice,   MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zsys_mod, "info",    mrb_zsys_info,     MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zsys_mod, "debug",   mrb_zsys_debug,    MRB_ARGS_REQ(1));

  zsock_class = mrb_define_class_under(mrb, czmq_mod, "Zsock", mrb->object_class);
  MRB_SET_INSTANCE_TT(zsock_class, MRB_TT_DATA);
  mrb_define_method(mrb,        zsock_class, "initialize",  mrb_zsock_initialize,   MRB_ARGS_NONE());
  mrb_define_class_method(mrb,  zsock_class, "new_stream",  mrb_zsock_new_stream,   MRB_ARGS_REQ(1));
  mrb_define_method(mrb,        zsock_class, "signal",      mrb_zsock_signal,       MRB_ARGS_OPT(1));
  mrb_define_method(mrb,        zsock_class, "wait",        mrb_zsock_wait,         MRB_ARGS_NONE());

  callback_class = mrb_define_class_under(mrb, czmq_mod, "Callback", mrb->object_class);
  MRB_SET_INSTANCE_TT(callback_class, MRB_TT_DATA);

  zloop_class = mrb_define_class_under(mrb, czmq_mod, "Zloop", mrb->object_class);
  MRB_SET_INSTANCE_TT(zloop_class, MRB_TT_DATA);
  mrb_define_method(mrb, zloop_class, "initialize",     mrb_zloop_new,              MRB_ARGS_NONE());
  mrb_define_method(mrb, zloop_class, "timer",          mrb_zloop_timer,            MRB_ARGS_REQ(3));
  mrb_define_method(mrb, zloop_class, "timer_end",      mrb_zloop_timer_end,        MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zloop_class, "ticket_delay=",  mrb_zloop_set_ticket_delay, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zloop_class, "ticket",         mrb_zloop_ticket,           MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zloop_class, "ticket_reset",   mrb_zloop_ticket_reset,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zloop_class, "ticket_delete",  mrb_zloop_ticket_delete,    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zloop_class, "reader",         mrb_zloop_reader,           MRB_ARGS_REQ(2));
  mrb_define_method(mrb, zloop_class, "reader_end",     mrb_zloop_reader_end,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zloop_class, "verbose=",       mrb_zloop_set_verbose,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zloop_class, "start",          mrb_zloop_start,            MRB_ARGS_NONE());

  zframe_class = mrb_define_class_under(mrb, czmq_mod, "Zframe", mrb->object_class);
  mrb_define_const(mrb, zframe_class, "MORE",      mrb_fixnum_value(ZFRAME_MORE));
  mrb_define_const(mrb, zframe_class, "REUSE",     mrb_fixnum_value(ZFRAME_REUSE));
  mrb_define_const(mrb, zframe_class, "DONTWAIT",  mrb_fixnum_value(ZFRAME_DONTWAIT));
  MRB_SET_INSTANCE_TT(zframe_class, MRB_TT_DATA);
  mrb_define_method(mrb, zframe_class, "initialize",    mrb_zframe_new,     MRB_ARGS_OPT(1));
  mrb_define_module_function(mrb, zframe_class, "recv", mrb_zframe_recv,    MRB_ARGS_NONE());
  mrb_define_method(mrb, zframe_class, "data",          mrb_zframe_data,    MRB_ARGS_NONE());
  mrb_define_method(mrb, zframe_class, "size",          mrb_zframe_size,    MRB_ARGS_NONE());
  mrb_define_method(mrb, zframe_class, "to_str",        mrb_zframe_to_str,  MRB_ARGS_NONE());
  mrb_define_method(mrb, zframe_class, "reset" ,        mrb_zframe_reset,   MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zframe_class, "send" ,         mrb_zframe_send,    MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, zframe_class, "more?" ,        mrb_zframe_more,    MRB_ARGS_NONE());

  zactor_class = mrb_define_class_under(mrb, czmq_mod, "Zactor", mrb->object_class);
  mrb_define_module_function(mrb, zactor_class, "new_auth",     mrb_zactor_new_zauth,     MRB_ARGS_NONE());
  mrb_define_module_function(mrb, zactor_class, "new_beacon",   mrb_zactor_new_zbeacon,   MRB_ARGS_NONE());
  mrb_define_module_function(mrb, zactor_class, "new_gossip",   mrb_zactor_new_zgossip,   MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zactor_class, "new_monitor",  mrb_zactor_new_zmonitor,  MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zactor_class, "new_proxy",    mrb_zactor_new_zproxy,    MRB_ARGS_NONE());

  zconfig_class = mrb_define_class_under(mrb, czmq_mod, "Zconfig", mrb->object_class);
  MRB_SET_INSTANCE_TT(zconfig_class, MRB_TT_DATA);
  mrb_define_method(mrb, zconfig_class, "initialize", mrb_zconfig_new,          MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, zconfig_class, "name",       mrb_zconfig_name,         MRB_ARGS_NONE());
  mrb_define_method(mrb, zconfig_class, "value",      mrb_zconfig_value,        MRB_ARGS_NONE());
  mrb_define_method(mrb, zconfig_class, "put",        mrb_zconfig_put,          MRB_ARGS_REQ(2));
  mrb_define_method(mrb, zconfig_class, "name=",      mrb_zconfig_set_name,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zconfig_class, "value=",     mrb_zconfig_set_value,    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zconfig_class, "resolve",    mrb_zconfig_resolve,      MRB_ARGS_ARG(1, 1));
  mrb_define_module_function(mrb, zconfig_class, "load",  mrb_zconfig_load,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zconfig_class, "save",       mrb_zconfig_save,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zconfig_class, "filename",   mrb_zconfig_filename,     MRB_ARGS_NONE());
  mrb_define_method(mrb, zconfig_class, "reload",     mrb_zconfig_reload,       MRB_ARGS_NONE());
  mrb_define_method(mrb, zconfig_class, "changed?",   mrb_zconfig_has_changed,  MRB_ARGS_NONE());

  if (zsys_init() == NULL)
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

void
mrb_mruby_czmq_gem_final(mrb_state* mrb) {

}
