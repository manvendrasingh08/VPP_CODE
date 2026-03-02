#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>

typedef struct {
    u64 packet_count;
} pktcounter_main_t;

pktcounter_main_t pktcounter_main;

/* Next node index */
typedef enum {
    PKTCOUNTER_NEXT_LOOKUP,
    PKTCOUNTER_N_NEXT,
} pktcounter_next_t;

/* Node function */
static uword
pktcounter_node_fn (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * frame)
{
    u32 *from = vlib_frame_vector_args(frame);
    u32 n_left_from = frame->n_vectors;

    pktcounter_main.packet_count += n_left_from;

    /* allocate next array */
    u16 nexts[VLIB_FRAME_SIZE];
    for (u32 i = 0; i < n_left_from; i++)
        nexts[i] = PKTCOUNTER_NEXT_LOOKUP;

    /* forward packets */
    vlib_buffer_enqueue_to_next(vm, node, from, nexts, n_left_from);

    return n_left_from;
}
/* Register node */
VLIB_REGISTER_NODE(pktcounter_node) = {
    .name = "pktcounter-node",
    .function = pktcounter_node_fn,
    .vector_size = sizeof(u32),
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_next_nodes = PKTCOUNTER_N_NEXT,
    .next_nodes = {
        [PKTCOUNTER_NEXT_LOOKUP] = "ip4-lookup",
    },
};

/* Register feature for forwarded traffic */
VNET_FEATURE_INIT (pktcounter_feature) = {
    .arc_name = "ip4-unicast",
    .node_name = "pktcounter-node",
    .runs_before = 0,
};

/* Register feature for local traffic */
VNET_FEATURE_INIT (pktcounter_feature_local) = {
    .arc_name = "ip4-local",
    .node_name = "pktcounter-node",
    .runs_before = 0,
};

/* CLI */
static clib_error_t *
show_pktcounter_fn (vlib_main_t * vm,
                    unformat_input_t * input,
                    vlib_cli_command_t * cmd)
{
    vlib_cli_output(vm, "Packets seen: %lu",
        pktcounter_main.packet_count);
    return 0;
}

VLIB_CLI_COMMAND (show_pktcounter_cmd, static) = {
    .path = "show pktcounter",
    .short_help = "show pktcounter",
    .function = show_pktcounter_fn,
};

/* Plugin register */
VLIB_PLUGIN_REGISTER () = {
    .version = "1.0",
    .description = "Simple packet counter plugin",
};
