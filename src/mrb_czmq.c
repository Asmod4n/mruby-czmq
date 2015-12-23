#include "mruby/czmq.h"
#include "mrb_czmq.h"

static mrb_value
mrb_zclock_sleep(mrb_state* mrb, mrb_value self)
{
    mrb_int msecs;

    mrb_get_args(mrb, "i", &msecs);

    if (msecs < INT_MIN || msecs > INT_MAX)
        mrb_raise(mrb, E_RANGE_ERROR, "msecs is out of range");

    zclock_sleep(msecs);

    return self;
}

static mrb_value
mrb_zclock_time(mrb_state* mrb, mrb_value self)
{
#ifdef MRB_INT64
    return mrb_fixnum_value(zclock_time());
#else
    return mrb_float_value(mrb, zclock_time());
#endif
}

static mrb_value
mrb_zclock_mono(mrb_state* mrb, mrb_value self)
{
#ifdef MRB_INT64
    return mrb_fixnum_value(zclock_mono());
#else
    return mrb_float_value(mrb, zclock_mono());
#endif
}

static mrb_value
mrb_zclock_usecs(mrb_state* mrb, mrb_value self)
{
#ifdef MRB_INT64
    return mrb_fixnum_value(zclock_usecs());
#else
    return mrb_float_value(mrb, zclock_usecs());
#endif
}

static mrb_value
mrb_zclock_timestr(mrb_state* mrb, mrb_value self)
{
    errno = 0;
    char* timestr = zclock_timestr();
    if (timestr) {
        mrb_value time_obj = mrb_str_new_cstr(mrb, timestr);
        zstr_free(&timestr);
        return time_obj;
    }
    else
        mrb_sys_fail(mrb, "zclock_timestr");

    return self;
}

static mrb_value
mrb_zsys_error(mrb_state* mrb, mrb_value self)
{
    char* msg;

    mrb_get_args(mrb, "z", &msg);

    zsys_error("%s", msg);

    return self;
}

static mrb_value
mrb_zsys_warning(mrb_state* mrb, mrb_value self)
{
    char* msg;

    mrb_get_args(mrb, "z", &msg);

    zsys_warning("%s", msg);

    return self;
}

static mrb_value
mrb_zsys_notice(mrb_state* mrb, mrb_value self)
{
    char* msg;

    mrb_get_args(mrb, "z", &msg);

    zsys_notice("%s", msg);

    return self;
}

static mrb_value
mrb_zsys_info(mrb_state* mrb, mrb_value self)
{
    char* msg;

    mrb_get_args(mrb, "z", &msg);

    zsys_info("%s", msg);

    return self;
}

static mrb_value
mrb_zsys_debug(mrb_state* mrb, mrb_value self)
{
    char* msg;

    mrb_get_args(mrb, "z", &msg);

    zsys_debug("%s", msg);

    return self;
}

static mrb_value
mrb_zsys_interface(mrb_state* mrb, mrb_value self)
{
    const char* interface = zsys_interface();

    return mrb_str_new_static(mrb, interface, strlen(interface));
}

static mrb_value
mrb_zsys_interrupted(mrb_state* mrb, mrb_value self)
{
    if (zsys_interrupted)
        return mrb_true_value();
    else
        return mrb_false_value();
}

static mrb_value
mrb_set_zsys_interrupted(mrb_state* mrb, mrb_value self)
{
    mrb_bool interrupted;

    mrb_get_args(mrb, "b", &interrupted);

    zctx_interrupted = zsys_interrupted = (int)interrupted;

    return self;
}

static mrb_value
mrb_zsys_create_pipe(mrb_state* mrb, mrb_value self)
{
    errno = 0;
    zsock_t* backend;
    zsock_t* frontend = zsys_create_pipe(&backend);

    if (frontend) {
        return mrb_assoc_new(mrb,
            mrb_obj_value(mrb_data_object_alloc(mrb,
                mrb_class_get_under(mrb,
                                                    mrb_module_get(mrb, "CZMQ"), "Zsock"),
                frontend, &mrb_zsock_actor_type)),
            mrb_obj_value(mrb_data_object_alloc(mrb,
                mrb_class_get_under(mrb,
                                                    mrb_module_get(mrb, "CZMQ"), "Zsock"),
                backend, &mrb_zsock_actor_type)));
    }
    else
        mrb_sys_fail(mrb, "zsys_create_pipe");

    return self;
}

static mrb_value
mrb_zsys_hostname(mrb_state* mrb, mrb_value self)
{
    char* hostname = zsys_hostname();
    if (hostname) {
        mrb_value hostname_obj = mrb_str_new_cstr(mrb, hostname);
        zstr_free(&hostname);
        return hostname_obj;
    }

    return mrb_nil_value();
}

static mrb_value
mrb_zsock_new_from(mrb_state* mrb, mrb_value self)
{
    mrb_value zsock_value;
    mrb_bool fresh = FALSE;

    mrb_get_args(mrb, "o|b", &zsock_value, &fresh);

    if (!mrb_cptr_p(zsock_value))
        mrb_raise(mrb, E_ARGUMENT_ERROR, "zsock must be a c pointer");

    void* zsock = mrb_cptr(zsock_value);
    mrb_assert(zsock);
    mrb_assert(zsock_is(zsock));

    if (fresh) {
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self),
            zsock, &mrb_zsock_actor_type));
    }
    else {
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self),
            zsock, NULL));
    }
}

static mrb_value
mrb_zsock_new(mrb_state* mrb, mrb_value self)
{
    mrb_int type;
    zsock_t* zsock;

    mrb_get_args(mrb, "i", &type);

    if (type < INT_MIN || type > INT_MAX)
        mrb_raise(mrb, E_RANGE_ERROR, "type is ouf of range");

    errno = 0;

    zsock = zsock_new((int)type);
    if (zsock)
        mrb_data_init(self, zsock, &mrb_zsock_actor_type);
    else
        mrb_sys_fail(mrb, "zsock_new");

    return self;
}

static mrb_value
mrb_zsock_bind(mrb_state* mrb, mrb_value self)
{
    char* endpoint;
    int port;

    mrb_get_args(mrb, "z", &endpoint);

    errno = 0;

    port = zsock_bind((zsock_t*)DATA_PTR(self), "%s", endpoint);
    if (port != -1) {
#ifndef MRB_INT64
        if (port > MRB_INT_MAX)
            return mrb_float_value(mrb, port);
        else
#endif
            return mrb_fixnum_value(port);
    }
    else
        mrb_sys_fail(mrb, "zsock_bind");

    return self;
}

static mrb_value
mrb_zsock_unbind(mrb_state* mrb, mrb_value self)
{
    char* endpoint;

    mrb_get_args(mrb, "z", &endpoint);

    errno = 0;

    if (zsock_unbind((zsock_t*)DATA_PTR(self), "%s", endpoint) == -1) {
        mrb_sys_fail(mrb, "zsock_unbind");
    }
    return self;
}

static mrb_value
mrb_zsock_connect(mrb_state* mrb, mrb_value self)
{
    char* endpoint;

    mrb_get_args(mrb, "z", &endpoint);

    errno = 0;

    if (zsock_connect((zsock_t*)DATA_PTR(self), "%s", endpoint) == -1) {
        mrb_sys_fail(mrb, "zsock_connect");
    }

    return self;
}

static mrb_value
mrb_zsock_disconnect(mrb_state* mrb, mrb_value self)
{
    char* endpoint;

    mrb_get_args(mrb, "z", &endpoint);

    errno = 0;

    if (zsock_disconnect((zsock_t*)DATA_PTR(self), "%s", endpoint) == -1) {
        mrb_sys_fail(mrb, "zsock_disconnect");
    }

    return self;
}

static mrb_value
mrb_zsock_attach(mrb_state* mrb, mrb_value self)
{
    char* endpoints;
    mrb_bool serverish = FALSE;

    mrb_get_args(mrb, "z|b", &endpoints, &serverish);

    errno = 0;

    if (zsock_attach((zsock_t*)DATA_PTR(self), endpoints, serverish) == -1) {
        mrb_sys_fail(mrb, "zsock_attach");
    }

    return self;
}

static mrb_value
mrb_zsock_type_str(mrb_state* mrb, mrb_value self)
{
    const char* type = zsock_type_str((zsock_t*)DATA_PTR(self));

    return mrb_str_new_static(mrb, type, strlen(type));
}

static mrb_value
mrb_zsock_signal(mrb_state* mrb, mrb_value self)
{
    mrb_int status = 0;

    mrb_get_args(mrb, "|i", &status);

    if (status < 0 || status > UCHAR_MAX)
        mrb_raise(mrb, E_RANGE_ERROR, "status is out of range");

    errno = 0;

    if (zsock_signal(DATA_PTR(self), (byte)status) == -1) {
        mrb_sys_fail(mrb, "zsock_signal");
    }

    return self;
}

static mrb_value
mrb_zsock_wait(mrb_state* mrb, mrb_value self)
{
    return mrb_fixnum_value(zsock_wait(DATA_PTR(self)));
}

static mrb_value
mrb_zsock_endpoint(mrb_state* mrb, mrb_value self)
{
    const char* endpoint = zsock_endpoint((zsock_t*)DATA_PTR(self));
    if (endpoint)
        return mrb_str_new_cstr(mrb, endpoint);
    else
        return mrb_nil_value();
}

static mrb_value
mrb_zsock_set_identity(mrb_state* mrb, mrb_value self)
{
    char* identity;

    mrb_get_args(mrb, "z", &identity);

    zsock_set_identity((zsock_t*)DATA_PTR(self), identity);

    return self;
}

static mrb_value
mrb_zsock_identity(mrb_state* mrb, mrb_value self)
{
#ifdef ZMQ_IDENTITY
    uint8_t id[255];
    size_t id_size = 255;
    zmq_getsockopt(zsock_resolve(DATA_PTR(self)), ZMQ_IDENTITY, id, &id_size);
    return mrb_str_new(mrb, (const char*)id, id_size);
#else
    return mrb_nil_value();
#endif
}

static mrb_value
mrb_zsock_set_subscribe(mrb_state* mrb, mrb_value self)
{
#ifdef ZMQ_SUBSCRIBE
    if (zsock_type(DATA_PTR(self)) != ZMQ_SUB) {
        const char* sockname = zsys_sockname(zsock_type(DATA_PTR(self)));
        mrb_value sockstr = mrb_str_new_static(mrb, sockname, strlen(sockname));
        mrb_raisef(mrb, E_CZMQ_ERROR, "ZMQ_SUBSCRIBE is not valid on %S sockets", sockstr);
    }
    char* subscribe;
    mrb_int subscribe_len;

    mrb_get_args(mrb, "s", &subscribe, &subscribe_len);

    errno = 0;
    int rc = zmq_setsockopt(zsock_resolve(DATA_PTR(self)), ZMQ_SUBSCRIBE, subscribe, subscribe_len);
    if (rc == -1)
        mrb_sys_fail(mrb, "zsock_set_subscribe");

    return self;
#endif
    return mrb_nil_value();
}

static mrb_value
mrb_zsock_set_unsubscribe(mrb_state* mrb, mrb_value self)
{
#ifdef ZMQ_UNSUBSCRIBE
    if (zsock_type(DATA_PTR(self)) != ZMQ_SUB) {
        const char* sockname = zsys_sockname(zsock_type(DATA_PTR(self)));
        mrb_value sockstr = mrb_str_new_static(mrb, sockname, strlen(sockname));
        mrb_raisef(mrb, E_CZMQ_ERROR, "ZMQ_UNSUBSCRIBE is not valid on %S sockets", sockstr);
    }
    char* unsubscribe;
    mrb_int unsubscribe_len;

    mrb_get_args(mrb, "s", &unsubscribe, &unsubscribe_len);

    errno = 0;
    int rc = zmq_setsockopt(zsock_resolve(DATA_PTR(self)), ZMQ_UNSUBSCRIBE, unsubscribe, unsubscribe_len);
    if (rc == -1)
        mrb_sys_fail(mrb, "zsock_set_unsubscribe");

    return self;
#endif
    return mrb_nil_value();
}

static mrb_value
mrb_zsock_set_rcvtimeo(mrb_state *mrb, mrb_value self)
{
    mrb_int rcvtimeo;

    mrb_get_args(mrb, "i", &rcvtimeo);

    zsock_set_rcvtimeo(DATA_PTR(self), rcvtimeo);

    return self;
}

static mrb_value
mrb_zsock_set_sndtimeo(mrb_state *mrb, mrb_value self)
{
    mrb_int sndtimeo;

    mrb_get_args(mrb, "i", &sndtimeo);

    zsock_set_sndtimeo(DATA_PTR(self), sndtimeo);

    return self;
}

static mrb_value
mrb_zsock_sendx(mrb_state* mrb, mrb_value self)
{
    mrb_value* argv;
    mrb_int argc;
    zmsg_t* msg;
    mrb_value* argv_end;
    mrb_value s;

    mrb_get_args(mrb, "*", &argv, &argc);

    if (argc < 1)
        mrb_raise(mrb, E_ARGUMENT_ERROR, "wrong number of Arguments");

    errno = 0;

    msg = zmsg_new();
    if (msg) {
        argv_end = argv + argc;
        struct mrb_jmpbuf* prev_jmp = mrb->jmp;
        struct mrb_jmpbuf c_jmp;

        MRB_TRY(&c_jmp)
        {
            mrb->jmp = &c_jmp;
            int ai = mrb_gc_arena_save(mrb);
            for (; argv < argv_end; argv++) {
                s = mrb_str_to_str(mrb, *argv);
                if (zmsg_addmem(msg, RSTRING_PTR(s), RSTRING_LEN(s)) == -1) {
                    zmsg_destroy(&msg);
                    mrb_sys_fail(mrb, "zmsg_addmem");
                }
                mrb_gc_arena_restore(mrb, ai);
            }
            if (zmsg_send(&msg, DATA_PTR(self)) == -1) {
                zmsg_destroy(&msg);
                mrb_sys_fail(mrb, "zmsg_send");
            }
            mrb->jmp = prev_jmp;
        }
        MRB_CATCH(&c_jmp)
        {
            mrb->jmp = prev_jmp;
            zmsg_destroy(&msg);
            MRB_THROW(mrb->jmp);
        }
        MRB_END_EXC(&c_jmp);
    }
    else
        mrb_sys_fail(mrb, "zmsg_new");

    return self;
}

static mrb_value
mrb_zframe_new(mrb_state* mrb, mrb_value self)
{
    char* data = NULL;
    mrb_int size = 0;
    zframe_t* zframe;

    mrb_get_args(mrb, "|s", &data, &size);

    errno = 0;

    zframe = zframe_new(data, size);
    if (zframe)
        mrb_data_init(self, zframe, &mrb_zframe_type);
    else
        mrb_sys_fail(mrb, "zframe_new");

    return self;
}

static mrb_value
mrb_zframe_recv(mrb_state* mrb, mrb_value self)
{
    void* zsock_actor;
    zframe_t* zframe;

    mrb_get_args(mrb, "d", &zsock_actor, &mrb_zsock_actor_type);

    errno = 0;

    zframe = zframe_recv(zsock_actor);
    if (zframe)
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self),
            zframe, &mrb_zframe_type));
    else
        mrb_sys_fail(mrb, "zframe_recv");

    return self;
}

static mrb_value
mrb_zframe_data(mrb_state* mrb, mrb_value self)
{
    return mrb_cptr_value(mrb, zframe_data((zframe_t*)DATA_PTR(self)));
}

static mrb_value
mrb_zframe_size(mrb_state* mrb, mrb_value self)
{
    size_t size = zframe_size((zframe_t*)DATA_PTR(self));
    if (size > MRB_INT_MAX)
        return mrb_float_value(mrb, size);
    else
        return mrb_fixnum_value(size);
}

static mrb_value
mrb_zframe_to_str(mrb_state* mrb, mrb_value self)
{
    mrb_bool static_string = FALSE;

    mrb_get_args(mrb, "|b", &static_string);

    zframe_t* zframe = (zframe_t*)DATA_PTR(self);

    if (static_string)
        return mrb_str_new_static(mrb, zframe_data(zframe), zframe_size(zframe));
    else
        return mrb_str_new(mrb, zframe_data(zframe), zframe_size(zframe));
}

static mrb_value
mrb_zframe_reset(mrb_state* mrb, mrb_value self)
{
    char* data;
    mrb_int size;

    mrb_get_args(mrb, "s", &data, &size);

    zframe_reset((zframe_t*)DATA_PTR(self), data, (size_t)size);

    return self;
}

static mrb_value
mrb_zframe_send(mrb_state* mrb, mrb_value self)
{
    void* zsock_actor;
    mrb_int flags = 0;

    mrb_get_args(mrb, "d|i", &zsock_actor, &mrb_zsock_actor_type, &flags);

    if (flags < 0 || flags > INT_MAX)
        mrb_raise(mrb, E_RANGE_ERROR, "flags are out of range");

    errno = 0;
    size_t _size = zframe_size((zframe_t*)DATA_PTR(self));

    if (zframe_send((zframe_t**)&DATA_PTR(self), zsock_actor, (int)flags) == 0) {
        DATA_TYPE(self) = NULL;
        return mrb_fixnum_value(_size);
    }
    else
        mrb_sys_fail(mrb, "zframe_send");

    return self;
}

static mrb_value
mrb_zframe_more(mrb_state* mrb, mrb_value self)
{
    if (zframe_more((zframe_t*)DATA_PTR(self)))
        return mrb_true_value();
    else
        return mrb_false_value();
}

static mrb_value
mrb_zsock_recvx(mrb_state* mrb, mrb_value self)
{
    zmsg_t* msg = NULL;
    mrb_value msgs;
    zframe_t* zframe = NULL;

    errno = 0;

    msg = zmsg_recv(DATA_PTR(self));
    if (msg) {
        struct mrb_jmpbuf* prev_jmp = mrb->jmp;
        struct mrb_jmpbuf c_jmp;
        MRB_TRY(&c_jmp)
        {
            mrb->jmp = &c_jmp;
            msgs = mrb_ary_new_capa(mrb, zmsg_size(msg));
            int ai = mrb_gc_arena_save(mrb);
            zframe = zmsg_pop(msg);
            while (zframe) {
                mrb_value s = mrb_str_new(mrb, zframe_data(zframe), zframe_size(zframe));
                zframe_destroy(&zframe);
                mrb_ary_push(mrb, msgs, s);
                mrb_gc_arena_restore(mrb, ai);
                zframe = zmsg_pop(msg);
            }
            zmsg_destroy(&msg);
            mrb->jmp = prev_jmp;
        }
        MRB_CATCH(&c_jmp)
        {
            mrb->jmp = prev_jmp;
            zframe_destroy(&zframe);
            zmsg_destroy(&msg);
            MRB_THROW(mrb->jmp);
        }
        MRB_END_EXC(&c_jmp);

        return msgs;
    }
    else
        mrb_sys_fail(mrb, "zmsg_recv");

    return self;
}

static mrb_value
mrb_zactor_new_zauth(mrb_state* mrb, mrb_value self)
{
    errno = 0;
    zactor_t* zactor = zactor_new(zauth, NULL);
    if (zactor)
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self), zactor, &mrb_zsock_actor_type));
    else
        mrb_sys_fail(mrb, "zactor_new_zauth");

    return self;
}

static mrb_value
mrb_zactor_new_zbeacon(mrb_state* mrb, mrb_value self)
{
    errno = 0;
    zactor_t* zactor = zactor_new(zbeacon, NULL);
    if (zactor)
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self), zactor, &mrb_zsock_actor_type));
    else
        mrb_sys_fail(mrb, "zactor_new_zbeacon");

    return self;
}

static mrb_value
mrb_zactor_new_zgossip(mrb_state* mrb, mrb_value self)
{
    char* prefix = NULL;
    zactor_t* zactor;

    mrb_get_args(mrb, "|z!", &prefix);

    errno = 0;

    zactor = zactor_new(zgossip, prefix);
    if (zactor)
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self), zactor, &mrb_zsock_actor_type));
    else
        mrb_sys_fail(mrb, "zactor_new_zgossip");

    return self;
}

static mrb_value
mrb_zactor_new_zmonitor(mrb_state* mrb, mrb_value self)
{
    void* zsock_actor;
    zactor_t* zactor;

    mrb_get_args(mrb, "d", &zsock_actor, &mrb_zsock_actor_type);

    errno = 0;

    zactor = zactor_new(zmonitor, zsock_actor);
    if (zactor)
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self), zactor, &mrb_zsock_actor_type));
    else
        mrb_sys_fail(mrb, "zactor_new_zmonitor");

    return self;
}

static mrb_value
mrb_zactor_new_zproxy(mrb_state* mrb, mrb_value self)
{
    errno = 0;
    zactor_t* zactor = zactor_new(zproxy, NULL);
    if (zactor)
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self), zactor, &mrb_zsock_actor_type));
    else
        mrb_sys_fail(mrb, "zactor_new_zproxy");

    return self;
}

static mrb_value
mrb_zconfig_new(mrb_state* mrb, mrb_value self)
{
    char* name = (char*)"root";
    zconfig_t* config;

    mrb_get_args(mrb, "|z", &name);

    errno = 0;

    config = zconfig_new(name, NULL);
    if (config)
        mrb_data_init(self, config, &mrb_zconfig_type);
    else
        mrb_sys_fail(mrb, "zconfig_new");

    return self;
}

static mrb_value
mrb_zconfig_name(mrb_state* mrb, mrb_value self)
{
    char* name = zconfig_name((zconfig_t*)DATA_PTR(self));
    if (name)
        return mrb_str_new_cstr(mrb, name);
    else
        return mrb_nil_value();
}

static mrb_value
mrb_zconfig_value(mrb_state* mrb, mrb_value self)
{
    char* value = zconfig_value((zconfig_t*)DATA_PTR(self));
    if (value)
        return mrb_str_new_cstr(mrb, value);
    else
        return mrb_nil_value();
}

static mrb_value
mrb_zconfig_put(mrb_state* mrb, mrb_value self)
{
    char *path, *value;

    mrb_get_args(mrb, "zz", &path, &value);

    zconfig_put((zconfig_t*)DATA_PTR(self), path, value);

    return self;
}

static mrb_value
mrb_zconfig_set_name(mrb_state* mrb, mrb_value self)
{
    char* name;

    mrb_get_args(mrb, "z", &name);

    zconfig_set_name((zconfig_t*)DATA_PTR(self), name);

    return self;
}

static mrb_value
mrb_zconfig_set_value(mrb_state* mrb, mrb_value self)
{
    char* value;

    mrb_get_args(mrb, "z", &value);

    zconfig_set_value((zconfig_t*)DATA_PTR(self), "%s", value);

    return self;
}

static mrb_value
mrb_zconfig_resolve(mrb_state* mrb, mrb_value self)
{
    char *path, *default_value = NULL, *value;

    mrb_get_args(mrb, "z|z!", &path, &default_value);

    value = zconfig_resolve((zconfig_t*)DATA_PTR(self), path, default_value);
    if (value)
        return mrb_str_new_cstr(mrb, value);
    else
        return mrb_nil_value();
}

static mrb_value
mrb_zconfig_set_comment(mrb_state* mrb, mrb_value self)
{
    char* comment;

    mrb_get_args(mrb, "z", &comment);

    zconfig_set_comment((zconfig_t*)DATA_PTR(self), "%s", comment);

    return self;
}

static mrb_value
mrb_zconfig_comments(mrb_state* mrb, mrb_value self)
{
    zlist_t* comments;
    mrb_value comments_obj;
    const char* s;

    comments = zconfig_comments((zconfig_t*)DATA_PTR(self));
    if (comments) {
        comments_obj = mrb_ary_new_capa(mrb, zlist_size(comments));
        int ai = mrb_gc_arena_save(mrb);

        s = (const char*)zlist_first(comments);
        while (s) {
            mrb_ary_push(mrb, comments_obj, mrb_str_new_cstr(mrb, s));
            mrb_gc_arena_restore(mrb, ai);
            s = (const char*)zlist_next(comments);
        }

        return comments_obj;
    }
    else
        return mrb_nil_value();
}

static mrb_value
mrb_zconfig_load(mrb_state* mrb, mrb_value self)
{
    char* filename;
    zconfig_t* zconfig;

    mrb_get_args(mrb, "z", &filename);

    errno = 0;

    zconfig = zconfig_load(filename);
    if (zconfig)
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self),
            zconfig, &mrb_zconfig_type));
    else
        mrb_sys_fail(mrb, "zconfig_load");

    return self;
}

static mrb_value
mrb_zconfig_save(mrb_state* mrb, mrb_value self)
{
    char* filename;

    mrb_get_args(mrb, "z", &filename);

    errno = 0;

    if (zconfig_save((zconfig_t*)DATA_PTR(self), filename) == -1) {
        mrb_sys_fail(mrb, "zconfig_save");
    }

    return self;
}

static mrb_value
mrb_zconfig_filename(mrb_state* mrb, mrb_value self)
{
    const char* filename = zconfig_filename((zconfig_t*)DATA_PTR(self));
    if (filename)
        return mrb_str_new_static(mrb, filename, strlen(filename));
    else
        return mrb_nil_value();
}

static mrb_value
mrb_zconfig_reload(mrb_state* mrb, mrb_value self)
{
    errno = 0;
    if (zconfig_reload((zconfig_t**)&DATA_PTR(self)) == -1) {
        mrb_sys_fail(mrb, "zconfig_reload");
    }

    return self;
}

static mrb_value
mrb_zconfig_has_changed(mrb_state* mrb, mrb_value self)
{
    if (zconfig_has_changed((zconfig_t*)DATA_PTR(self)))
        return mrb_true_value();
    else
        return mrb_false_value();
}

static inline void*
mrb_czmq_resolve_sock(mrb_state* mrb, void* self)
{
    assert(self);
    if (zsock_is(self))
        return zsock_resolve(self);
    else if (zactor_is(self))
        return zactor_resolve(self);
    else
        mrb_raise(mrb, E_ARGUMENT_ERROR, "socket not resolveable");
}

static mrb_value
mrb_pollitem_new(mrb_state* mrb, mrb_value self)
{
    mrb_value socket_or_fd = mrb_nil_value();
    mrb_int events = ZMQ_POLLIN;

    mrb_get_args(mrb, "|oi", &socket_or_fd, &events);

    if (events < SHRT_MIN || events > SHRT_MAX)
        mrb_raise(mrb, E_RANGE_ERROR, "events are out of range");

    zmq_pollitem_t* pollitem = mrb_calloc(mrb, 1, sizeof(zmq_pollitem_t));
    mrb_data_init(self, pollitem, &mrb_pollitem_type);

    switch (mrb_type(socket_or_fd)) {
    case MRB_TT_CPTR:
        pollitem->socket = mrb_cptr(socket_or_fd);
        break;
    case MRB_TT_DATA: {
        if (mrb_respond_to(mrb, socket_or_fd, mrb_intern_lit(mrb, "fileno"))) {
            mrb_value fileno = mrb_funcall(mrb, socket_or_fd, "fileno", 0);
            pollitem->fd = mrb_int(mrb, fileno);
        }
        else
            pollitem->socket = mrb_czmq_resolve_sock(mrb, DATA_PTR(socket_or_fd));
    } break;
    case MRB_TT_FIXNUM:
        pollitem->fd = mrb_fixnum(socket_or_fd);
        break;
    case MRB_TT_FALSE:
        break;
    default:
        mrb_raise(mrb, E_ARGUMENT_ERROR, "data type not supported");
    }

    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "socket"), socket_or_fd);

    pollitem->events = events;

    return self;
}

static mrb_value
mrb_pollitem_socket(mrb_state* mrb, mrb_value self)
{
    return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "socket"));
}

static mrb_value
mrb_pollitem_events(mrb_state* mrb, mrb_value self)
{
    return mrb_fixnum_value(((zmq_pollitem_t*)DATA_PTR(self))->events);
}

static mrb_value
mrb_pollitem_set_events(mrb_state* mrb, mrb_value self)
{
    zmq_pollitem_t* pollitem = (zmq_pollitem_t*)DATA_PTR(self);

    mrb_int events;

    mrb_get_args(mrb, "i", &events);

    if (events < SHRT_MIN || events > SHRT_MAX)
        mrb_raise(mrb, E_RANGE_ERROR, "events are out of range");

    pollitem->events = events;

    return self;
}

static mrb_value
mrb_pollitem_revents(mrb_state* mrb, mrb_value self)
{
    return mrb_fixnum_value(((zmq_pollitem_t*)DATA_PTR(self))->revents);
}

static mrb_value
mrb_zmq_poll(mrb_state* mrb, mrb_value self)
{
    mrb_value* pollitems_obj;
    mrb_int pollitems_len, timeout;

    mrb_get_args(mrb, "ai", &pollitems_obj, &pollitems_len, &timeout);

    if (timeout * ZMQ_POLL_MSEC < LONG_MIN || timeout * ZMQ_POLL_MSEC > LONG_MAX)
        mrb_raise(mrb, E_RANGE_ERROR, "timeout is out of range");

    zmq_pollitem_t pollitems[pollitems_len];

    for (mrb_int i = 0; i < pollitems_len; i++)
        pollitems[i] = *DATA_CHECK_GET_PTR(mrb, pollitems_obj[i], &mrb_pollitem_type, zmq_pollitem_t);

    errno = 0;
    int rc = zmq_poll(pollitems, pollitems_len, timeout * ZMQ_POLL_MSEC);

    switch (rc) {
    case -1:
        if (zsys_interrupted || errno == EINTR)
            return mrb_false_value();
        else
            mrb_sys_fail(mrb, "zmq_poll");
        break;
    case 0:
        return mrb_nil_value();
        break;
    case 1: {
        for (mrb_int i = 0; i < pollitems_len; i++) {
            if (pollitems[i].revents) {
                ((zmq_pollitem_t*)DATA_PTR(pollitems_obj[i]))->revents = pollitems[i].revents;
                return pollitems_obj[i];
            }
        }
    } break;
    default: {
        mrb_value signaled_items = mrb_ary_new_capa(mrb, rc);

        for (mrb_int i = 0; i < pollitems_len; i++) {
            if (pollitems[i].revents) {
                ((zmq_pollitem_t*)DATA_PTR(pollitems_obj[i]))->revents = pollitems[i].revents;
                mrb_ary_push(mrb, signaled_items, pollitems_obj[i]);
            }
        }

        return signaled_items;
    }
    }

    return self;
}

static mrb_value
mrb_actor_new(mrb_state* mrb, mrb_value self)
{
    mrb_value mrb_actor_obj;
    const char* mrb_actor_args = NULL;

    mrb_get_args(mrb, "o|z!", &mrb_actor_obj, &mrb_actor_args);

    if (!mrb_cptr_p(mrb_actor_obj))
        mrb_raise(mrb, E_ARGUMENT_ERROR, "mrb_actor_obj must be a c pointer");

    zactor_t* zactor = zactor_new(mrb_cptr(mrb_actor_obj), mrb_actor_args);
    if (zactor)
        mrb_data_init(self, zactor, &mrb_zsock_actor_type);
    else
        mrb_sys_fail(mrb, "zactor_new_mrb_zactor_fn");

    return self;
}

static mrb_value
mrb_zmsg_recv(mrb_state* mrb, mrb_value self)
{
    void* zsock_actor;
    zmsg_t* zmsg;

    mrb_get_args(mrb, "d", &zsock_actor, &mrb_zsock_actor_type);

    errno = 0;
    zmsg = zmsg_recv(zsock_actor);
    if (zmsg)
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self),
            zmsg, &mrb_zmsg_type));
    else
        mrb_sys_fail(mrb, "zmsg_recv");

    return self;
}

static mrb_value
mrb_zmsg_new_from(mrb_state* mrb, mrb_value self)
{
    mrb_value zmsg_value;
    mrb_bool fresh = FALSE;

    mrb_get_args(mrb, "o|b", &zmsg_value, &fresh);

    if (!mrb_cptr_p(zmsg_value))
        mrb_raise(mrb, E_ARGUMENT_ERROR, "zmsg must be a c pointer");

    void* zmsg = mrb_cptr(zmsg_value);
    mrb_assert(zmsg);
    mrb_assert(zmsg_is(zmsg));

    if (fresh) {
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self),
            zmsg, &mrb_zmsg_type));
    }
    else {
        return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self),
            zmsg, NULL));
    }
}

static mrb_value
mrb_zmsg_new(mrb_state* mrb, mrb_value self)
{
    mrb_value* argv;
    mrb_int argc = 0;
    zmsg_t* msg;
    mrb_value* argv_end;
    mrb_value s;

    mrb_get_args(mrb, "|a", &argv, &argc);

    errno = 0;

    msg = zmsg_new();
    if (msg)
        mrb_data_init(self, msg, &mrb_zmsg_type);
    else
        mrb_sys_fail(mrb, "zmsg_new");

    if (argc > 0) {
        int ai = mrb_gc_arena_save(mrb);
        argv_end = argv + argc;
        for (; argv < argv_end; argv++) {
            s = mrb_str_to_str(mrb, *argv);
            if (zmsg_addmem(msg, RSTRING_PTR(s), RSTRING_LEN(s)) == -1) {
                zmsg_destroy(&msg);
                mrb_sys_fail(mrb, "zmsg_addmem");
            }
            mrb_gc_arena_restore(mrb, ai);
        }
    }

    return self;
}

static mrb_value
mrb_zmsg_send(mrb_state* mrb, mrb_value self)
{
    void* zsock_actor;

    mrb_get_args(mrb, "d", &zsock_actor, &mrb_zsock_actor_type);

    errno = 0;
    int rc = zmsg_send((zmsg_t**) &DATA_PTR(self), zsock_actor);
    if (rc == 0) {
        DATA_TYPE(self) = NULL;
    } else {
        mrb_sys_fail(mrb, "zmsg_send");
    }

    return mrb_nil_value();
}

static mrb_value
mrb_zmsg_to_ary(mrb_state* mrb, mrb_value self)
{
    zmsg_t* msg = (zmsg_t*)DATA_PTR(self);
    mrb_value msgs = mrb_ary_new_capa(mrb, zmsg_size(msg));
    int ai = mrb_gc_arena_save(mrb);
    zframe_t* zframe = zmsg_first(msg);
    while (zframe) {
        mrb_value s = mrb_str_new(mrb, zframe_data(zframe), zframe_size(zframe));
        mrb_ary_push(mrb, msgs, s);
        mrb_gc_arena_restore(mrb, ai);
        zframe = zmsg_next(msg);
    }

    return msgs;
}

void mrb_mruby_czmq_gem_init(mrb_state* mrb)
{
    struct RClass *zmq_mod, *zmq_version_mod, *czmq_mod, *czmq_version_mod, *zclock_mod, *zsys_mod, *zsock_actor_class, *zsock_class,
        *zframe_class, *zactor_class, *zconfig_class, *pollitem_class, *zmsg_class;

    zmq_mod = mrb_define_module(mrb, "ZMQ");
    mrb_define_const(mrb, zmq_mod, "PAIR", mrb_fixnum_value(ZMQ_PAIR));
    mrb_define_const(mrb, zmq_mod, "PUB", mrb_fixnum_value(ZMQ_PUB));
    mrb_define_const(mrb, zmq_mod, "SUB", mrb_fixnum_value(ZMQ_SUB));
    mrb_define_const(mrb, zmq_mod, "REQ", mrb_fixnum_value(ZMQ_REQ));
    mrb_define_const(mrb, zmq_mod, "REP", mrb_fixnum_value(ZMQ_REP));
    mrb_define_const(mrb, zmq_mod, "DEALER", mrb_fixnum_value(ZMQ_DEALER));
    mrb_define_const(mrb, zmq_mod, "ROUTER", mrb_fixnum_value(ZMQ_ROUTER));
    mrb_define_const(mrb, zmq_mod, "PULL", mrb_fixnum_value(ZMQ_PULL));
    mrb_define_const(mrb, zmq_mod, "PUSH", mrb_fixnum_value(ZMQ_PUSH));
    mrb_define_const(mrb, zmq_mod, "XPUB", mrb_fixnum_value(ZMQ_XPUB));
    mrb_define_const(mrb, zmq_mod, "XSUB", mrb_fixnum_value(ZMQ_XSUB));
    mrb_define_const(mrb, zmq_mod, "STREAM", mrb_fixnum_value(ZMQ_STREAM));
#ifdef ZMQ_SERVER
    mrb_define_const(mrb, zmq_mod, "SERVER", mrb_fixnum_value(ZMQ_SERVER));
#endif
#ifdef ZMQ_CLIENT
    mrb_define_const(mrb, zmq_mod, "CLIENT", mrb_fixnum_value(ZMQ_CLIENT));
#endif
    mrb_define_const(mrb, zmq_mod, "POLLIN", mrb_fixnum_value(ZMQ_POLLIN));
    mrb_define_const(mrb, zmq_mod, "POLLOUT", mrb_fixnum_value(ZMQ_POLLOUT));
    mrb_define_const(mrb, zmq_mod, "POLLERR", mrb_fixnum_value(ZMQ_POLLERR));
#ifdef ZMQ_POLLPRI
    mrb_define_const(mrb, zmq_mod, "POLLPRI", mrb_fixnum_value(ZMQ_POLLPRI));
#endif
    zmq_version_mod = mrb_define_module_under(mrb, zmq_mod, "VERSION");
    mrb_define_const(mrb, zmq_version_mod, "MAJOR", mrb_fixnum_value(ZMQ_VERSION_MAJOR));
    mrb_define_const(mrb, zmq_version_mod, "MINOR", mrb_fixnum_value(ZMQ_VERSION_MINOR));
    mrb_define_const(mrb, zmq_version_mod, "PATCH", mrb_fixnum_value(ZMQ_VERSION_PATCH));

    mrb_define_module_function(mrb, zmq_mod, "poll", mrb_zmq_poll, MRB_ARGS_REQ(2));

    czmq_mod = mrb_define_module(mrb, "CZMQ");
    mrb_define_class_under(mrb, czmq_mod, "Error", E_RUNTIME_ERROR);
    mrb_define_const(mrb, czmq_mod, "ZUUID_LEN", mrb_fixnum_value(ZUUID_LEN));
    czmq_version_mod = mrb_define_module_under(mrb, czmq_mod, "VERSION");
    mrb_define_const(mrb, czmq_version_mod, "MAJOR", mrb_fixnum_value(CZMQ_VERSION_MAJOR));
    mrb_define_const(mrb, czmq_version_mod, "MINOR", mrb_fixnum_value(CZMQ_VERSION_MINOR));
    mrb_define_const(mrb, czmq_version_mod, "PATCH", mrb_fixnum_value(CZMQ_VERSION_PATCH));

    zclock_mod = mrb_define_module_under(mrb, czmq_mod, "Zclock");
    mrb_define_module_function(mrb, zclock_mod, "sleep", mrb_zclock_sleep, MRB_ARGS_REQ(1));
    mrb_define_module_function(mrb, zclock_mod, "time", mrb_zclock_time, MRB_ARGS_NONE());
    mrb_define_module_function(mrb, zclock_mod, "mono", mrb_zclock_mono, MRB_ARGS_NONE());
    mrb_define_module_function(mrb, zclock_mod, "usecs", mrb_zclock_usecs, MRB_ARGS_NONE());
    mrb_define_module_function(mrb, zclock_mod, "timestr", mrb_zclock_timestr, MRB_ARGS_NONE());

    zsys_mod = mrb_define_module_under(mrb, czmq_mod, "Zsys");
    mrb_define_module_function(mrb, zsys_mod, "error", mrb_zsys_error, MRB_ARGS_REQ(1));
    mrb_define_module_function(mrb, zsys_mod, "warning", mrb_zsys_warning, MRB_ARGS_REQ(1));
    mrb_define_module_function(mrb, zsys_mod, "notice", mrb_zsys_notice, MRB_ARGS_REQ(1));
    mrb_define_module_function(mrb, zsys_mod, "info", mrb_zsys_info, MRB_ARGS_REQ(1));
    mrb_define_module_function(mrb, zsys_mod, "debug", mrb_zsys_debug, MRB_ARGS_REQ(1));
    mrb_define_module_function(mrb, zsys_mod, "interface", mrb_zsys_interface, MRB_ARGS_NONE());
    mrb_define_module_function(mrb, zsys_mod, "interrupted?", mrb_zsys_interrupted, MRB_ARGS_NONE());
    mrb_define_module_function(mrb, zsys_mod, "interrupted=", mrb_set_zsys_interrupted, MRB_ARGS_REQ(1));
    mrb_define_module_function(mrb, zsys_mod, "create_pipe", mrb_zsys_create_pipe, MRB_ARGS_NONE());
    mrb_define_module_function(mrb, zsys_mod, "hostname", mrb_zsys_hostname, MRB_ARGS_NONE());

    zsock_actor_class = mrb_define_class_under(mrb, czmq_mod, "ZsockActor", mrb->object_class);
    MRB_SET_INSTANCE_TT(zsock_actor_class, MRB_TT_DATA);
    mrb_define_method(mrb, zsock_actor_class, "signal", mrb_zsock_signal, MRB_ARGS_OPT(1));
    mrb_define_method(mrb, zsock_actor_class, "wait", mrb_zsock_wait, MRB_ARGS_NONE());
    mrb_define_method(mrb, zsock_actor_class, "sendx", mrb_zsock_sendx, MRB_ARGS_ANY());
    mrb_define_method(mrb, zsock_actor_class, "recvx", mrb_zsock_recvx, MRB_ARGS_NONE());

    zsock_class = mrb_define_class_under(mrb, czmq_mod, "Zsock", zsock_actor_class);
    mrb_define_class_method(mrb, zsock_class, "new_from", mrb_zsock_new_from, MRB_ARGS_ARG(1, 1));
    mrb_define_method(mrb, zsock_class, "initialize", mrb_zsock_new, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zsock_class, "bind", mrb_zsock_bind, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zsock_class, "unbind", mrb_zsock_unbind, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zsock_class, "connect", mrb_zsock_connect, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zsock_class, "disconnect", mrb_zsock_disconnect, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zsock_class, "attach", mrb_zsock_attach, MRB_ARGS_ARG(1, 1));
    mrb_define_method(mrb, zsock_class, "type_str", mrb_zsock_type_str, MRB_ARGS_NONE());
    mrb_define_method(mrb, zsock_class, "endpoint", mrb_zsock_endpoint, MRB_ARGS_NONE());
    mrb_define_method(mrb, zsock_class, "identity=", mrb_zsock_set_identity, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zsock_class, "identity", mrb_zsock_identity, MRB_ARGS_NONE());
    mrb_define_method(mrb, zsock_class, "subscribe=", mrb_zsock_set_subscribe, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zsock_class, "unsubscribe=", mrb_zsock_set_unsubscribe, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zsock_class, "rcvtimeo=", mrb_zsock_set_rcvtimeo, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zsock_class, "sndtimeo=", mrb_zsock_set_sndtimeo, MRB_ARGS_REQ(1));


    zframe_class = mrb_define_class_under(mrb, czmq_mod, "Zframe", mrb->object_class);
    MRB_SET_INSTANCE_TT(zframe_class, MRB_TT_DATA);
    mrb_define_const(mrb, zframe_class, "MORE", mrb_fixnum_value(ZFRAME_MORE));
    mrb_define_const(mrb, zframe_class, "REUSE", mrb_fixnum_value(ZFRAME_REUSE));
    mrb_define_const(mrb, zframe_class, "DONTWAIT", mrb_fixnum_value(ZFRAME_DONTWAIT));
    mrb_define_method(mrb, zframe_class, "initialize", mrb_zframe_new, MRB_ARGS_OPT(1));
    mrb_define_class_method(mrb, zframe_class, "recv", mrb_zframe_recv, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zframe_class, "data", mrb_zframe_data, MRB_ARGS_NONE());
    mrb_define_method(mrb, zframe_class, "size", mrb_zframe_size, MRB_ARGS_NONE());
    mrb_define_method(mrb, zframe_class, "to_str", mrb_zframe_to_str, MRB_ARGS_OPT(1));
    mrb_define_method(mrb, zframe_class, "reset", mrb_zframe_reset, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zframe_class, "send", mrb_zframe_send, MRB_ARGS_ARG(1, 1));
    mrb_define_method(mrb, zframe_class, "more?", mrb_zframe_more, MRB_ARGS_NONE());

    zactor_class = mrb_define_class_under(mrb, czmq_mod, "Zactor", zsock_actor_class);
    mrb_define_method(mrb, zactor_class, "initialize", mrb_actor_new, MRB_ARGS_REQ(1));
    mrb_define_class_method(mrb, zactor_class, "new_zauth", mrb_zactor_new_zauth, MRB_ARGS_NONE());
    mrb_define_class_method(mrb, zactor_class, "new_zbeacon", mrb_zactor_new_zbeacon, MRB_ARGS_NONE());
    mrb_define_class_method(mrb, zactor_class, "new_zgossip", mrb_zactor_new_zgossip, MRB_ARGS_OPT(1));
    mrb_define_class_method(mrb, zactor_class, "new_zmonitor", mrb_zactor_new_zmonitor, MRB_ARGS_REQ(1));
    mrb_define_class_method(mrb, zactor_class, "new_zproxy", mrb_zactor_new_zproxy, MRB_ARGS_NONE());

    zconfig_class = mrb_define_class_under(mrb, czmq_mod, "Zconfig", mrb->object_class);
    MRB_SET_INSTANCE_TT(zconfig_class, MRB_TT_DATA);
    mrb_define_method(mrb, zconfig_class, "initialize", mrb_zconfig_new, MRB_ARGS_OPT(1));
    mrb_define_method(mrb, zconfig_class, "name", mrb_zconfig_name, MRB_ARGS_NONE());
    mrb_define_method(mrb, zconfig_class, "value", mrb_zconfig_value, MRB_ARGS_NONE());
    mrb_define_method(mrb, zconfig_class, "put", mrb_zconfig_put, MRB_ARGS_REQ(2));
    mrb_define_method(mrb, zconfig_class, "name=", mrb_zconfig_set_name, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zconfig_class, "value=", mrb_zconfig_set_value, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zconfig_class, "comment=", mrb_zconfig_set_comment, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zconfig_class, "comments", mrb_zconfig_comments, MRB_ARGS_NONE());
    mrb_define_method(mrb, zconfig_class, "resolve", mrb_zconfig_resolve, MRB_ARGS_ARG(1, 1));
    mrb_define_class_method(mrb, zconfig_class, "load", mrb_zconfig_load, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zconfig_class, "save", mrb_zconfig_save, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zconfig_class, "filename", mrb_zconfig_filename, MRB_ARGS_NONE());
    mrb_define_method(mrb, zconfig_class, "reload", mrb_zconfig_reload, MRB_ARGS_NONE());
    mrb_define_method(mrb, zconfig_class, "changed?", mrb_zconfig_has_changed, MRB_ARGS_NONE());

    pollitem_class = mrb_define_class_under(mrb, zmq_mod, "Pollitem", mrb->object_class);
    MRB_SET_INSTANCE_TT(pollitem_class, MRB_TT_DATA);
    mrb_define_method(mrb, pollitem_class, "initialize", mrb_pollitem_new, MRB_ARGS_OPT(2));
    mrb_define_method(mrb, pollitem_class, "socket", mrb_pollitem_socket, MRB_ARGS_NONE());
    mrb_define_method(mrb, pollitem_class, "events", mrb_pollitem_events, MRB_ARGS_NONE());
    mrb_define_method(mrb, pollitem_class, "events=", mrb_pollitem_set_events, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, pollitem_class, "revents", mrb_pollitem_revents, MRB_ARGS_NONE());

    zmsg_class = mrb_define_class_under(mrb, czmq_mod, "Zmsg", mrb->object_class);
    MRB_SET_INSTANCE_TT(zmsg_class, MRB_TT_DATA);
    mrb_define_class_method(mrb, zmsg_class, "new_from", mrb_zmsg_new_from, MRB_ARGS_ARG(1, 1));
    mrb_define_class_method(mrb, zmsg_class, "recv", mrb_zmsg_recv, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zmsg_class, "initialize", mrb_zmsg_new, MRB_ARGS_OPT(1));
    mrb_define_method(mrb, zmsg_class, "send", mrb_zmsg_send, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, zmsg_class, "to_ary", mrb_zmsg_to_ary, MRB_ARGS_NONE());

#ifdef __WINDOWS__
    if (sizeof(SOCKET) > sizeof(mrb_int))
        mrb_warn(mrb, "enable #define MRB_INT%S in mrbconf.h for mruby-czmq or else you cannot poll on TCP Sockets\n", mrb_fixnum_value(sizeof(SOCKET) * 8));
#endif

    errno = 0;
    if (zsys_init() == NULL)
        mrb_sys_fail(mrb, "zsys_init");
}

void mrb_mruby_czmq_gem_final(mrb_state* mrb)
{
}
