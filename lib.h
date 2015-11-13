#ifndef __GOLIB_WIRESHARK_H__
#define __GOLIB_WIRESHARK_H__

#define HAVE_STDARG_H 1
#define WS_MSVC_NORETURN

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wireshark/epan/epan.h>
#include <wireshark/epan/epan_dissect.h>
#include <wireshark/epan/print.h>
#include <wireshark/epan/timestamp.h>
#include <wireshark/epan/prefs.h>
#include <wireshark/epan/column.h>
#include <wireshark/epan/epan-int.h>
#include <wireshark/wsutil/privileges.h>
#include <wireshark/epan/asm_utils.h>

#define BUFSIZE 2048 * 100

//global variable
capture_file cfile;


int init(char *filename);

void clean();

void print_xml_packet();

void print_field_value(char *name);

struct epan_dissect *next_packet();

char *get_field_value(struct epan_dissect *edt, char *name);

void free_packet(struct epan_dissect *edt);

void free_string(char *s);

char *print_packet(proto_tree *node);

char *print_node(proto_node *node);

proto_node *get_field(struct epan_dissect *edt, const char *name);

static void proto_node_print(proto_tree *tree, int *level, char **buf);

static void print_field(proto_node *node, int *level, char **buf);

extern tvbuff_t *frame_tvbuff_new(const frame_data *fd, const guint8 *buf);

static gboolean read_packet(epan_dissect_t **edt_r);

static void timestamp_set(capture_file cfile);

static const nstime_t *tshark_get_frame_ts(void *data, guint32 frame_num);

//static gboolean find_field(struct epan_dissect *edt, const char *name, char **value);

static gboolean proto_tree_pre_order(proto_tree *tree, const char *name, proto_node **node);

#endif  /* __GOLIB_WIRESHARK_H__ */
