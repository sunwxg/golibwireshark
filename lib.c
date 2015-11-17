#include <lib.h>

static e_prefs *get_prefs()
{
	e_prefs     *prefs_p;
	char        *gpf_path, *pf_path;
	int          gpf_read_errno, gpf_open_errno;
	int          pf_open_errno, pf_read_errno;

	prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
			&pf_open_errno, &pf_read_errno, &pf_path);
	return prefs_p;
}

int init_cfile(char *filename)
{
	int          err;
	gchar       *err_info = NULL;

	cap_file_init(&cfile);
	cfile.filename = filename;

	cfile.wth = wtap_open_offline(cfile.filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
	if (cfile.wth == NULL) {
		return err;
	}

	cfile.count = 0;
	cfile.epan = epan_new();
	cfile.epan->data = &cfile;
	cfile.epan->get_frame_ts = tshark_get_frame_ts;

	timestamp_set(cfile);
	cfile.frames = new_frame_data_sequence();

	return 0;
}

int init_pdh(char *savefile)
{
	int err;

	if (savefile != NULL){
		if (!open_output_file(savefile, &err)) {
			return err;
		}
	}

	return 0;
}

int init(char *filename, char *savefile)
{
	int          err = 0;
	e_prefs     *prefs_p;

	init_process_policies();

	epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL);

	err = init_cfile(filename);
	if (err != 0)
		goto fail;

	err = init_pdh(savefile);
	if (err != 0)
		goto fail;

	prefs_p = get_prefs();

	build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

	return 0;
fail:
	clean();
	return 1;
}

static gboolean read_packet(epan_dissect_t **edt_r)
{
	epan_dissect_t    *edt;
	int                err;
	gchar             *err_info = NULL;
	static guint32     cum_bytes = 0;
	static gint64      data_offset = 0;

	struct wtap_pkthdr *whdr = wtap_phdr(cfile.wth);
	guchar             *buf = wtap_buf_ptr(cfile.wth);

	if (wtap_read(cfile.wth, &err, &err_info, &data_offset)) {

		cfile.count++;

		frame_data fdlocal;
		frame_data_init(&fdlocal, cfile.count, whdr, data_offset, cum_bytes);

		edt = epan_dissect_new(cfile.epan, TRUE, TRUE);

		frame_data_set_before_dissect(&fdlocal, &cfile.elapsed_time,
			       	&cfile.ref, cfile.prev_dis);
		cfile.ref = &fdlocal;

		epan_dissect_run(edt, cfile.cd_t, &(cfile.phdr),
				frame_tvbuff_new(&fdlocal, buf), &fdlocal, &cfile.cinfo);

		frame_data_set_after_dissect(&fdlocal, &cum_bytes);
		cfile.prev_cap = cfile.prev_dis = frame_data_sequence_add(cfile.frames, &fdlocal);

		//free space
		frame_data_destroy(&fdlocal);

		*edt_r = edt;
		return TRUE;
	}
	return FALSE;
}

void clean()
{
	int err = 0;

	if (cfile.frames != NULL) {
		free_frame_data_sequence(cfile.frames);
		cfile.frames = NULL;
	}

	if (cfile.wth != NULL) {
		wtap_close(cfile.wth);
		cfile.wth = NULL;
	}

	if (pdh != NULL) {
		wtap_dump_close(pdh, &err);
	}

	if (cfile.epan != NULL)
		epan_free(cfile.epan);

	epan_cleanup();
}

void clean_cfile()
{
	if (cfile.frames != NULL) {
		free_frame_data_sequence(cfile.frames);
		cfile.frames = NULL;
	}

	if (cfile.wth != NULL) {
		wtap_close(cfile.wth);
		cfile.wth = NULL;
	}

	if (cfile.epan != NULL)
		epan_free(cfile.epan);
}

void clean_pdh()
{
	int err = 0;

	if (pdh != NULL) {
		wtap_dump_close(pdh, &err);
	}
}

static void
timestamp_set(capture_file cfile)
{
	switch(wtap_file_tsprecision(cfile.wth)) {
		case(WTAP_FILE_TSPREC_SEC):
			timestamp_set_precision(TS_PREC_AUTO_SEC);
			break;
		case(WTAP_FILE_TSPREC_DSEC):
			timestamp_set_precision(TS_PREC_AUTO_DSEC);
			break;
		case(WTAP_FILE_TSPREC_CSEC):
			timestamp_set_precision(TS_PREC_AUTO_CSEC);
			break;
		case(WTAP_FILE_TSPREC_MSEC):
			timestamp_set_precision(TS_PREC_AUTO_MSEC);
			break;
		case(WTAP_FILE_TSPREC_USEC):
			timestamp_set_precision(TS_PREC_AUTO_USEC);
			break;
		case(WTAP_FILE_TSPREC_NSEC):
			timestamp_set_precision(TS_PREC_AUTO_NSEC);
			break;
		default:
			g_assert_not_reached();
	}
}

static const nstime_t *
tshark_get_frame_ts(void *data, guint32 frame_num)
{
	capture_file *cf = (capture_file *) data;

	if (cf->ref && cf->ref->num == frame_num)
		return &(cf->ref->abs_ts);

	if (cf->prev_dis && cf->prev_dis->num == frame_num)
		return &(cf->prev_dis->abs_ts);

	if (cf->prev_cap && cf->prev_cap->num == frame_num)
		return &(cf->prev_cap->abs_ts);

	if (cf->frames) {
		frame_data *fd = frame_data_sequence_find(cf->frames, frame_num);

		return (fd) ? &fd->abs_ts : NULL;
	}

	return NULL;
}

void
cap_file_init(capture_file *cf)
{
	/* Initialize the capture file struct */
	memset(cf, 0, sizeof(capture_file));
	cf->snap            = WTAP_MAX_PACKET_SIZE;
}

char *
get_field_value(struct epan_dissect *edt, char *name)
{
	char *value;
	struct _proto_node *node;

	if (proto_tree_pre_order(edt->tree, name, &node)) {
		fvalue_t fv = node->finfo->value;
		value = fvalue_to_string_repr(&fv, FTREPR_DISPLAY, NULL);
		return value;
	}
	return NULL;
}

struct epan_dissect *next_packet()
{
	epan_dissect_t *edt;

	if (read_packet(&edt)) {
		return edt;
	};
	return NULL;
}

void
free_packet(struct epan_dissect *edt)
{
	epan_dissect_free(edt);
	edt = NULL;
}

void
free_string(char *s)
{
	free(s);
}

proto_node *
get_field(struct epan_dissect *edt, const char *name)
{
	proto_node *node;

	if (proto_tree_pre_order(edt->tree, name, &node)) {
		return node;
	}
	return NULL;
}

static gboolean
proto_tree_pre_order(proto_tree *tree, const char *name, proto_node **node)
{
	proto_node *pnode = tree;
	proto_node *child;
	proto_node *current;
	field_info *fi = PNODE_FINFO(pnode);

	if (fi && fi->hfinfo) {
		if (!strcmp(fi->hfinfo->abbrev, name)) {
			*node = pnode;
			return TRUE;
		}
	}

	child = pnode->first_child;
	while (child != NULL) {
		current = child;
		child   = current->next;
		if (proto_tree_pre_order((proto_tree *)current, name, node))
			return TRUE;
	}

	return FALSE;
}

char *print_packet(proto_tree *node)
{
	char *buf = calloc(sizeof(char), BUFSIZE);
	int level = 0;

	proto_node_print(node, &level, &buf);

	return buf;
}

char *print_node(proto_node *node)
{
	char *buf = calloc(sizeof(char), BUFSIZE);
	int level = 0;
	print_field(node, &level, &buf);

	level++;
	proto_node_print(node, &level, &buf);

	return buf;
}

static void
proto_node_print(proto_tree *tree, int *level, char **buf)
{
	proto_node *node = tree;
	proto_node *current;

	if (!node)
		return;

	node = node->first_child;
	while (node != NULL) {
		current = node;
		node    = current->next;

		print_field(current, level, buf);

		(*level)++;
		proto_node_print(current, level, buf);
		(*level)--;
	}
}

static void
print_field(proto_node *node, int *level, char **buf)
{
	if (node->finfo == NULL)
		return;

	//reset level when node is proto
        if (node->finfo->hfinfo->type == FT_PROTOCOL)
		*level = 0;

	for (int i = 0; i < *level; i++) {
		snprintf(*buf + strlen(*buf), BUFSIZE, "%s", ". ");
	}

	const char *name = node->finfo->hfinfo->abbrev;

	fvalue_t fv = node->finfo->value;
	char *value = fvalue_to_string_repr(&fv, FTREPR_DISPLAY, NULL);

	if (value == NULL) {
		snprintf(*buf + strlen(*buf), BUFSIZE, "[%s]\n", name);
	} else {
		snprintf(*buf + strlen(*buf), BUFSIZE, "[%s] %s\n", name, value);
	}
}

int  write_to_file()
{
	int err;
	if (pdh == NULL) {
		return 1;
	}

	if (!wtap_dump(pdh, wtap_phdr(cfile.wth), wtap_buf_ptr(cfile.wth), &err)) {
		return err;
	}
	return 0;
}

static gboolean
open_output_file(char *savefile, int *err)
{
	wtapng_section_t            *shb_hdr;
	wtapng_iface_descriptions_t *idb_inf;

	shb_hdr = wtap_file_get_shb_info(cfile.wth);
	idb_inf = wtap_file_get_idb_info(cfile.wth);

	guint snapshot_length = wtap_snapshot_length(cfile.wth);
	if (snapshot_length == 0) {
		snapshot_length = WTAP_MAX_PACKET_SIZE;
	}

	gint linktype = wtap_file_encap(cfile.wth);
	guint out_file_type = WTAP_FILE_TYPE_SUBTYPE_PCAP;

	pdh = wtap_dump_open_ng(savefile, out_file_type, linktype,
			snapshot_length, FALSE, shb_hdr, idb_inf, err);

	g_free(idb_inf);
	idb_inf = NULL;

	g_free(shb_hdr);
	shb_hdr = NULL;

	if (pdh == NULL) {
		return FALSE;
	}
	return TRUE;
}
