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

static mrb_value
mrb_zsys_interface(mrb_state *mrb, mrb_value self)
{
  const char *interface = zsys_interface();

  return mrb_str_new_static(mrb, interface, strlen(interface));
}

static mrb_value
mrb_zsys_interrupted(mrb_state *mrb, mrb_value self)
{
  if (zsys_interrupted == 0)
    return mrb_false_value();
  else
    return mrb_true_value();
}

static mrb_value
mrb_set_zsys_interrupted(mrb_state *mrb, mrb_value self)
{
  mrb_int interrupted;

  mrb_get_args(mrb, "i", &interrupted);

  if (interrupted < INT_MIN ||interrupted > INT_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "interrupted is out of range");

  zsys_interrupted = (int) interrupted;

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
mrb_zsock_new_stream(mrb_state *mrb, mrb_value self)
{
  char* endpoint = NULL;
  zsock_t *zsock;

  mrb_get_args(mrb, "|z", &endpoint);

  zsock = zsock_new_stream(endpoint);
  if (zsock)
    return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self),
      zsock, &mrb_zsock_actor_type));
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zsock_bind(mrb_state *mrb, mrb_value self)
{
  char *endpoint;
  int rc;

  mrb_get_args(mrb, "z", &endpoint);

  rc = zsock_bind((zsock_t *) DATA_PTR(self), "%s", endpoint);
  if (rc != -1)
    return mrb_fixnum_value(rc);
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zsock_unbind(mrb_state *mrb, mrb_value self)
{
  char *endpoint;

  mrb_get_args(mrb, "z", &endpoint);

  if (zsock_unbind((zsock_t *) DATA_PTR(self), "%s", endpoint) == 0)
    return self;
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zsock_connect(mrb_state *mrb, mrb_value self)
{
  char *endpoint;

  mrb_get_args(mrb, "z", &endpoint);

  if (zsock_connect((zsock_t *) DATA_PTR(self), "%s", endpoint) == 0)
    return self;
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zsock_disconnect(mrb_state *mrb, mrb_value self)
{
  char *endpoint;

  mrb_get_args(mrb, "z", &endpoint);

  if (zsock_disconnect((zsock_t *) DATA_PTR(self), "%s", endpoint) == 0)
    return self;
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zsock_attach(mrb_state *mrb, mrb_value self)
{
  char *endpoints;
  mrb_bool serverish_mruby = FALSE;
  bool serverish = false;

  mrb_get_args(mrb, "z|b", &endpoints, &serverish_mruby);

  if (serverish_mruby == TRUE)
    serverish = true;

  if (zsock_attach((zsock_t *) DATA_PTR(self), endpoints, serverish) == 0)
    return self;
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zsock_type_str(mrb_state *mrb, mrb_value self)
{
  const char *type = zsock_type_str((zsock_t *) DATA_PTR(self));

  return mrb_str_new_static(mrb, type, strlen(type));
}

static mrb_value
mrb_zsock_signal(mrb_state *mrb, mrb_value self)
{
  mrb_int status = 0;

  mrb_get_args(mrb, "|i", &status);

  if (status < 0 ||status > UCHAR_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "status is out of range");

  if (zsock_signal((zsock_t *) DATA_PTR(self), (byte) status) == 0)
    return self;
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zsock_wait(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(zsock_wait((zsock_t *) DATA_PTR(self)));
}

static mrb_value
mrb_zsock_endpoint(mrb_state *mrb, mrb_value self)
{
  const char *endpoint = zsock_endpoint((zsock_t *) DATA_PTR(self));
  if(endpoint)
    return mrb_str_new_static(mrb, endpoint, strlen(endpoint));
  else
    return mrb_nil_value();
}

static mrb_value
mrb_zsock_set_identity(mrb_state *mrb, mrb_value self)
{
  char *identity;

  mrb_get_args(mrb, "z", &identity);

  zsock_set_identity((zsock_t *) DATA_PTR(self), identity);

  return self;
}

static mrb_value
mrb_zsock_identity(mrb_state *mrb, mrb_value self)
{
  char *identity;
  mrb_value id_val;

  identity = zsock_identity((zsock_t *) DATA_PTR(self));
  if (identity) {
    id_val = mrb_str_new_cstr(mrb, identity);
    free(identity);
    return id_val;
  }
  else
    return mrb_nil_value();
}

static mrb_value
mrb_zsock_sendx(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv, s;
  mrb_int argc, i;
  zmsg_t *msg;

  mrb_get_args(mrb, "*", &argv, &argc);

  msg = zmsg_new();
  if (msg) {
    for (i = 0;i != argc;i++) {
      s = mrb_str_to_str(mrb, argv[i]);
      if (zmsg_addmem(msg, RSTRING_PTR(s), RSTRING_LEN(s)) == -1) {
        zmsg_destroy(&msg);
        mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
      }
    }

    if (zmsg_send(&msg, (zsock_t *) DATA_PTR(self)) == 0)
      return self;
    else {
      zmsg_destroy(&msg);
      mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
    }
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
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
  zframe_t *zframe;

  mrb_get_args(mrb, "|s", &data, &size);

  zframe = zframe_new(data, size);
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
  zframe_t *zframe;

  mrb_get_args(mrb, "d", &zsock_actor, &mrb_zsock_actor_type);

  zframe = zframe_recv(zsock_actor);
  if (zframe)
    return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self),
      zframe, &mrb_zframe_type));
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

  return mrb_str_new_static(mrb, (const char *) zframe_data(zframe),
    zframe_size(zframe));
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

  if (flags < 0 ||flags > INT_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "flags are out of range");

  if (zframe_send((zframe_t **) &DATA_PTR(self), zsock_actor, flags) == 0)
    return mrb_true_value();
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zframe_more(mrb_state *mrb, mrb_value self)
{
  if (zframe_more((zframe_t *) DATA_PTR(self)) == 0)
    return mrb_false_value();
  else
    return mrb_true_value();
}

static mrb_value
mrb_zsock_recvx(mrb_state *mrb, mrb_value self)
{
  zmsg_t *msg;
  mrb_value msgs;
  zframe_t *zframe;

  msg = zmsg_recv(DATA_PTR(self));
  if (msg) {
    msgs = mrb_ary_new_capa(mrb, zmsg_size(msg));
    zframe = zmsg_pop(msg);
    while (zframe) {
      mrb_ary_push(mrb, msgs, mrb_obj_value(mrb_data_object_alloc(mrb,
        mrb_class_get_under(mrb, mrb_module_get(mrb, "CZMQ"), "Zframe"),
        zframe, &mrb_zframe_type)));
      zframe = zmsg_pop(msg);
    }
    zmsg_destroy(&msg);

    return msgs;
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zactor_new_zauth(mrb_state *mrb, mrb_value self)
{
  zactor_t *zactor = zactor_new(zauth, NULL);
  if (zactor)
    return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), zactor, &mrb_zsock_actor_type));
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zactor_new_zbeacon(mrb_state *mrb, mrb_value self)
{
  zactor_t *zactor = zactor_new(zbeacon, NULL);
  if (zactor)
    return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), zactor, &mrb_zsock_actor_type));
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zactor_new_zgossip(mrb_state *mrb, mrb_value self)
{
  char *prefix = NULL;
  zactor_t *zactor;

  mrb_get_args(mrb, "|z", &prefix);

  zactor = zactor_new(zgossip, prefix);
  if (zactor)
    return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), zactor, &mrb_zsock_actor_type));
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zactor_new_zmonitor(mrb_state *mrb, mrb_value self)
{
  void *zsock_actor;
  zactor_t *zactor;

  mrb_get_args(mrb, "d", &zsock_actor, &mrb_zsock_actor_type);

  zactor = zactor_new(zmonitor, zsock_actor);
  if (zactor)
    return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), zactor, &mrb_zsock_actor_type));
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zactor_new_zproxy(mrb_state *mrb, mrb_value self)
{
  zactor_t *zactor = zactor_new(zproxy, NULL);
  if (zactor)
    return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_get_under(mrb,
      mrb_module_get(mrb, "CZMQ"), "Zsock"), zactor, &mrb_zsock_actor_type));
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
  char *name = "root";
  zconfig_t *config;

  mrb_get_args(mrb, "|z", &name);

  config = zconfig_new (name, NULL);
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
mrb_zconfig_set_comment(mrb_state *mrb, mrb_value self)
{
  char *comment;

  mrb_get_args(mrb, "z", &comment);

  zconfig_set_comment((zconfig_t *) DATA_PTR(self), "%s", comment);

  return self;
}

static mrb_value
mrb_zconfig_comments(mrb_state *mrb, mrb_value self)
{
  zlist_t *comments;
  mrb_value comments_obj;
  const char *s;

  comments = zconfig_comments((zconfig_t *) DATA_PTR(self));
  if (comments) {
    comments_obj = mrb_ary_new_capa(mrb, zlist_size(comments));

    s = (const char *) zlist_first(comments);
    while (s) {
      mrb_ary_push(mrb, comments_obj, mrb_str_new_static(mrb, s, strlen(s)));
      s = (const char *) zlist_next(comments);
    }

    return comments_obj;
  }
  else
    return mrb_nil_value();
}

static mrb_value
mrb_zconfig_load(mrb_state *mrb, mrb_value self)
{
  char *filename;
  zconfig_t *zconfig;

  mrb_get_args(mrb, "z", &filename);

  zconfig = zconfig_load(filename);
  if (zconfig)
    return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self),
      zconfig, &mrb_zconfig_type));
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

static void
mrb_zpoller_destroy(mrb_state *mrb, void *p)
{
  zpoller_destroy((zpoller_t **) &p);
}

static const struct mrb_data_type mrb_zpoller_type = {
  "$i_mrb_zpoller_type", mrb_zpoller_destroy
};

static mrb_value
mrb_zpoller_new(mrb_state *mrb, mrb_value self)
{
  mrb_value zsock_actor, sockets;
  void *zsocket;
  zpoller_t *poller;
  char poller_addr[sizeof(uintptr_t) * 2 + 3];

  mrb_get_args(mrb, "o", &zsock_actor);

  zsocket = mrb_data_get_ptr(mrb, zsock_actor, &mrb_zsock_actor_type);

  poller = zpoller_new(zsocket, NULL);
  if (poller) {
    mrb_data_init(self, poller, &mrb_zpoller_type);
    sockets = mrb_hash_new(mrb);
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "sockets"), sockets);
    mrb_assert(snprintf(poller_addr, sizeof(poller_addr), "%p", zsocket) < sizeof(poller_addr));
    mrb_hash_set(mrb, sockets, mrb_str_new_cstr(mrb, poller_addr),
      zsock_actor);
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));

  return self;
}

static mrb_value
mrb_zpoller_add(mrb_state *mrb, mrb_value self)
{
  mrb_value zsock_actor;
  void *zsocket;
  char poller_addr[sizeof(uintptr_t) * 2 + 3];

  mrb_get_args(mrb, "o", &zsock_actor);

  zsocket = mrb_data_get_ptr(mrb, zsock_actor, &mrb_zsock_actor_type);

  if (zpoller_add((zpoller_t *) DATA_PTR(self), zsocket) == 0) {
    mrb_assert(snprintf(poller_addr, sizeof(poller_addr), "%p", zsocket) < sizeof(poller_addr));
    mrb_hash_set(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb,
      "sockets")), mrb_str_new_cstr(mrb, poller_addr), zsock_actor);
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));

  return self;
}

static mrb_value
mrb_zpoller_remove(mrb_state *mrb, mrb_value self)
{
  mrb_value zsock_actor;
  void *zsocket;
  char poller_addr[sizeof(uintptr_t) * 2 + 3];

  mrb_get_args(mrb, "o", &zsock_actor);

  zsocket = mrb_data_get_ptr(mrb, zsock_actor, &mrb_zsock_actor_type);

  if (zpoller_remove((zpoller_t *) DATA_PTR(self), zsocket) == 0) {
    mrb_assert(snprintf(poller_addr, sizeof(poller_addr), "%p", zsocket) < sizeof(poller_addr));
    mrb_hash_delete_key(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb,
      "sockets")),  mrb_str_new_cstr(mrb, poller_addr));
    return self;
  }
  else
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

static mrb_value
mrb_zpoller_wait(mrb_state *mrb, mrb_value self)
{
  mrb_int timeout = -1;
  void *zsock_actor;
  char poller_addr[sizeof(uintptr_t) * 2 + 3];

  mrb_get_args(mrb, "|i", &timeout);

  if(timeout < -1 ||timeout > INT_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "timeout is out of range");

  zsock_actor = zpoller_wait((zpoller_t *) DATA_PTR(self), (int) timeout);
  if (zsock_actor) {
    snprintf(poller_addr, sizeof(poller_addr), "%p", zsock_actor);
    return mrb_hash_get(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb,
      "sockets")), mrb_str_new_cstr(mrb, poller_addr));
  }
  else
    return mrb_nil_value();
}

static mrb_value
mrb_zpoller_expired(mrb_state *mrb, mrb_value self)
{
  if (zpoller_expired((zpoller_t *) DATA_PTR(self)) == true)
    return mrb_true_value();
  else
    return mrb_false_value();
}

static mrb_value
mrb_zpoller_terminated(mrb_state *mrb, mrb_value self)
{
  if (zpoller_terminated((zpoller_t *) DATA_PTR(self)) == true)
    return mrb_true_value();
  else
    return mrb_false_value();
}

void
mrb_mruby_czmq_gem_init(mrb_state* mrb) {
  struct RClass *czmq_mod, *zsys_mod, *zsock_class,
  *zframe_class, *zactor_mod, *zconfig_class, *zpoller_class;

  czmq_mod = mrb_define_module(mrb, "CZMQ");
  mrb_define_class_under(mrb, czmq_mod, "Error", E_RUNTIME_ERROR);

  zsys_mod = mrb_define_module_under(mrb, czmq_mod, "Zsys");
  mrb_define_module_function(mrb, zsys_mod, "error",        mrb_zsys_error,           MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zsys_mod, "warning",      mrb_zsys_warning,         MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zsys_mod, "notice",       mrb_zsys_notice,          MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zsys_mod, "info",         mrb_zsys_info,            MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zsys_mod, "debug",        mrb_zsys_debug,           MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zsys_mod, "interface",    mrb_zsys_interface,       MRB_ARGS_NONE());
  mrb_define_module_function(mrb, zsys_mod, "interrupted?", mrb_zsys_interrupted,     MRB_ARGS_NONE());
  mrb_define_module_function(mrb, zsys_mod, "interrupted=", mrb_set_zsys_interrupted, MRB_ARGS_REQ(1));

  zsock_class = mrb_define_class_under(mrb, czmq_mod, "Zsock", mrb->object_class);
  MRB_SET_INSTANCE_TT(zsock_class, MRB_TT_DATA);
  mrb_define_class_method(mrb, zsock_class, "new_stream", mrb_zsock_new_stream, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, zsock_class, "bind",       mrb_zsock_bind,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zsock_class, "unbind",     mrb_zsock_unbind,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zsock_class, "connect",    mrb_zsock_connect,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zsock_class, "disconnect", mrb_zsock_disconnect,   MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zsock_class, "attach",     mrb_zsock_attach,       MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, zsock_class, "type_str",   mrb_zsock_type_str,     MRB_ARGS_NONE());
  mrb_define_method(mrb, zsock_class, "signal",     mrb_zsock_signal,       MRB_ARGS_OPT(1));
  mrb_define_method(mrb, zsock_class, "wait",       mrb_zsock_wait,         MRB_ARGS_NONE());
  mrb_define_method(mrb, zsock_class, "endpoint",   mrb_zsock_endpoint,     MRB_ARGS_NONE());
  mrb_define_method(mrb, zsock_class, "identity=",  mrb_zsock_set_identity, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zsock_class, "identity",   mrb_zsock_identity,     MRB_ARGS_NONE());
  mrb_define_method(mrb, zsock_class, "sendx",      mrb_zsock_sendx,        MRB_ARGS_ANY());
  mrb_define_method(mrb, zsock_class, "recvx",      mrb_zsock_recvx,        MRB_ARGS_NONE());

  zframe_class = mrb_define_class_under(mrb, czmq_mod, "Zframe", mrb->object_class);
  mrb_define_const(mrb, zframe_class, "MORE",      mrb_fixnum_value(ZFRAME_MORE));
  mrb_define_const(mrb, zframe_class, "REUSE",     mrb_fixnum_value(ZFRAME_REUSE));
  mrb_define_const(mrb, zframe_class, "DONTWAIT",  mrb_fixnum_value(ZFRAME_DONTWAIT));
  MRB_SET_INSTANCE_TT(zframe_class, MRB_TT_DATA);
  mrb_define_method(mrb, zframe_class, "initialize",    mrb_zframe_new,     MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, zframe_class, "recv",    mrb_zframe_recv,    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zframe_class, "data",          mrb_zframe_data,    MRB_ARGS_NONE());
  mrb_define_method(mrb, zframe_class, "size",          mrb_zframe_size,    MRB_ARGS_NONE());
  mrb_define_method(mrb, zframe_class, "to_str",        mrb_zframe_to_str,  MRB_ARGS_NONE());
  mrb_define_method(mrb, zframe_class, "reset" ,        mrb_zframe_reset,   MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zframe_class, "send" ,         mrb_zframe_send,    MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, zframe_class, "more?" ,        mrb_zframe_more,    MRB_ARGS_NONE());

  zactor_mod = mrb_define_module_under(mrb, czmq_mod, "Zactor");
  mrb_define_module_function(mrb, zactor_mod, "new_zauth",     mrb_zactor_new_zauth,     MRB_ARGS_NONE());
  mrb_define_module_function(mrb, zactor_mod, "new_zbeacon",   mrb_zactor_new_zbeacon,   MRB_ARGS_NONE());
  mrb_define_module_function(mrb, zactor_mod, "new_zgossip",   mrb_zactor_new_zgossip,   MRB_ARGS_OPT(1));
  mrb_define_module_function(mrb, zactor_mod, "new_zmonitor",  mrb_zactor_new_zmonitor,  MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, zactor_mod, "new_zproxy",    mrb_zactor_new_zproxy,    MRB_ARGS_NONE());

  zconfig_class = mrb_define_class_under(mrb, czmq_mod, "Zconfig", mrb->object_class);
  MRB_SET_INSTANCE_TT(zconfig_class, MRB_TT_DATA);
  mrb_define_method(mrb, zconfig_class, "initialize", mrb_zconfig_new,          MRB_ARGS_OPT(1));
  mrb_define_method(mrb, zconfig_class, "name",       mrb_zconfig_name,         MRB_ARGS_NONE());
  mrb_define_method(mrb, zconfig_class, "value",      mrb_zconfig_value,        MRB_ARGS_NONE());
  mrb_define_method(mrb, zconfig_class, "put",        mrb_zconfig_put,          MRB_ARGS_REQ(2));
  mrb_define_method(mrb, zconfig_class, "name=",      mrb_zconfig_set_name,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zconfig_class, "value=",     mrb_zconfig_set_value,    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zconfig_class, "comment=",   mrb_zconfig_set_comment,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zconfig_class, "comments",   mrb_zconfig_comments,     MRB_ARGS_NONE());
  mrb_define_method(mrb, zconfig_class, "resolve",    mrb_zconfig_resolve,      MRB_ARGS_ARG(1, 1));
  mrb_define_class_method(mrb, zconfig_class, "load", mrb_zconfig_load,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zconfig_class, "save",       mrb_zconfig_save,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zconfig_class, "filename",   mrb_zconfig_filename,     MRB_ARGS_NONE());
  mrb_define_method(mrb, zconfig_class, "reload",     mrb_zconfig_reload,       MRB_ARGS_NONE());
  mrb_define_method(mrb, zconfig_class, "changed?",   mrb_zconfig_has_changed,  MRB_ARGS_NONE());

  zpoller_class = mrb_define_class_under(mrb, czmq_mod, "Zpoller", mrb->object_class);
  MRB_SET_INSTANCE_TT(zpoller_class, MRB_TT_DATA);
  mrb_define_method(mrb, zpoller_class, "initialize",   mrb_zpoller_new,        MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zpoller_class, "add",          mrb_zpoller_add,        MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zpoller_class, "remove",       mrb_zpoller_remove,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, zpoller_class, "wait",         mrb_zpoller_wait,       MRB_ARGS_OPT(1));
  mrb_define_method(mrb, zpoller_class, "expired?",     mrb_zpoller_expired,    MRB_ARGS_NONE());
  mrb_define_method(mrb, zpoller_class, "terminated?",  mrb_zpoller_terminated, MRB_ARGS_NONE());

  if (zsys_init() == NULL)
    mrb_raise(mrb, E_CZMQ_ERROR, zmq_strerror(zmq_errno()));
}

void
mrb_mruby_czmq_gem_final(mrb_state* mrb) {

}
