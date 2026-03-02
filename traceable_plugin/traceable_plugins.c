#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vlib/unix/plugin.h>
#include <vnet/feature/feature.h>

/* ================= TRACE STRUCT ================= */

typedef struct
{
  u32 sw_if_index;
  u16 pkt_len;
} traceplugin_trace_t;

/* ================= GLOBAL STATE ================= */

typedef struct
{
  u64 packets;
} traceplugin_main_t;

traceplugin_main_t traceplugin_main;

/* ================= TRACE FORMATTER ================= */

static u8 *
format_traceplugin_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  traceplugin_trace_t * t = va_arg (*args, traceplugin_trace_t *);

  s = format (s, "traceplugin: sw_if_index %u len %u",
              t->sw_if_index, t->pkt_len);
  return s;
}

/* ================= NODE FUNCTION ================= */

VLIB_NODE_FN (traceplugin_node)
(vlib_main_t * vm,
 vlib_node_runtime_t * node,
 vlib_frame_t * frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;

  u16 nexts[VLIB_FRAME_SIZE];

  for (u32 i = 0; i < n_left_from; i++)
  {
    u32 bi0 = from[i];
    vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

    /* Increment packet counter */
    traceplugin_main.packets++;

    /* Trace support */
    if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
    {
      traceplugin_trace_t *t =
        vlib_add_trace (vm, node, b0, sizeof (*t));

      t->sw_if_index =
        vnet_buffer (b0)->sw_if_index[VLIB_RX];

      t->pkt_len =
        vlib_buffer_length_in_chain (vm, b0);
    }

    /* All packets go to next index 0 (ip4-lookup) */
    nexts[i] = 0;
  }

  /* Enqueue to next node */
  vlib_buffer_enqueue_to_next (vm, node,
                               from, nexts,
                               n_left_from);

  return n_left_from;
}

/* ================= NODE REGISTRATION ================= */

VLIB_REGISTER_NODE (traceplugin_node) = {
  .name = "traceplugin",
  .vector_size = sizeof (u32),
  .format_trace = format_traceplugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip4-lookup",
  },
};

/* ================= FEATURE ARC INSERTION ================= */

VNET_FEATURE_INIT (traceplugin_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "traceplugin",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

/* ================= CLI COMMAND ================= */

static clib_error_t *
show_traceplugin_fn (vlib_main_t * vm,
                     unformat_input_t * input,
                     vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "Packets seen: %lu",
                   traceplugin_main.packets);
  return 0;
}

VLIB_CLI_COMMAND (show_traceplugin, static) = {
  .path = "show traceplugin",
  .short_help = "show traceplugin",
  .function = show_traceplugin_fn,
};

/* ================= PLUGIN REGISTRATION ================= */

VLIB_PLUGIN_REGISTER () = {
  .version = "1.0",
  .description = "Trace Plugin with Packet Counter",
};