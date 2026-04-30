#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>

/* ===================== PLUGIN MAIN ===================== */
typedef struct {
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} myarp_main_t;

myarp_main_t myarp_main;

/* ===================== ARP HEADER ===================== */
typedef struct {
  u16 hardware_type;
  u16 protocol_type;
  u8 hardware_size;
  u8 protocol_size;
  u16 opcode;
  u8 sender_mac[6];
  u8 sender_ip[4];
  u8 target_mac[6];
  u8 target_ip[4];
} my_arp_header_t;

/* ===================== TRACE STRUCT ===================== */
typedef struct {
  u8 is_arp_packet;
  u16 opcode;
  u8 sender_mac[6];
  u8 target_mac[6];
  u32 sender_ip;
  u32 target_ip;
} my_arp_trace_t;

/* ===================== TRACE FORMATTER ===================== */
static u8 *
format_my_arp_trace (u8 * output, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  my_arp_trace_t * trace = va_arg (*args, my_arp_trace_t *);

  output = format(output, "MY-ARP-TRACE: ");

  if (!trace->is_arp_packet)
    return format(output, "Not ARP");

  output = format(output, "opcode %u ", trace->opcode);

  output = format(output, "sender-mac %U ",
                  format_ethernet_address, trace->sender_mac);

  output = format(output, "target-mac %U ",
                  format_ethernet_address, trace->target_mac);

  output = format(output, "sender-ip %U ",
                  format_ip4_address, &trace->sender_ip);

  output = format(output, "target-ip %U ",
                  format_ip4_address, &trace->target_ip);

  return output;
}

/* ===================== NODE FUNCTION ===================== */
static uword
my_arp_node_function (vlib_main_t * vm,
                      vlib_node_runtime_t * node_runtime,
                      vlib_frame_t * frame)
{
  u32 * packet_indices = vlib_frame_vector_args(frame);
  u32 packets_left = frame->n_vectors;

  while (packets_left > 0)
  {
    u32 current_packet_index = packet_indices[0];
    packet_indices++;
    packets_left--;

    vlib_buffer_t * current_packet_buffer =
      vlib_get_buffer(vm, current_packet_index);

    ethernet_header_t * ethernet_header =
      vlib_buffer_get_current(current_packet_buffer);

    u16 ethernet_type =
      clib_net_to_host_u16(ethernet_header->type);

    u32 next_node_index = 1; // drop

    /* TRACE */
    if (PREDICT_FALSE(current_packet_buffer->flags & VLIB_BUFFER_IS_TRACED))
    {
      my_arp_trace_t * trace_data =
        vlib_add_trace(vm, node_runtime,
                       current_packet_buffer,
                       sizeof(*trace_data));

      trace_data->is_arp_packet = (ethernet_type == 0x0806);

      if (trace_data->is_arp_packet)
      {
        my_arp_header_t * arp_header =
          (my_arp_header_t *)(ethernet_header + 1);

        trace_data->opcode =
          clib_net_to_host_u16(arp_header->opcode);

        clib_memcpy(trace_data->sender_mac,
                    arp_header->sender_mac, 6);

        clib_memcpy(trace_data->target_mac,
                    arp_header->target_mac, 6);

        clib_memcpy(&trace_data->sender_ip,
                    arp_header->sender_ip, 4);

        clib_memcpy(&trace_data->target_ip,
                    arp_header->target_ip, 4);
      }
    }

    /* MAIN LOGIC */
    if (ethernet_type == 0x0806)
    {
      my_arp_header_t * arp_header =
        (my_arp_header_t *)(ethernet_header + 1);

      u16 arp_opcode =
        clib_net_to_host_u16(arp_header->opcode);

      if (arp_opcode == 1) // request
      {
        u32 requested_ip;
        clib_memcpy(&requested_ip,
                    arp_header->target_ip, 4);

        /* 192.168.100.2 */
        if (requested_ip ==
            clib_host_to_net_u32(0xC0A86402))
        {
          u8 temp_mac[6];

          /* Ethernet swap */
          clib_memcpy(temp_mac,
                      ethernet_header->src_address, 6);

          clib_memcpy(ethernet_header->src_address,
                      ethernet_header->dst_address, 6);

          clib_memcpy(ethernet_header->dst_address,
                      temp_mac, 6);

          /* ARP MAC swap */
          clib_memcpy(temp_mac,
                      arp_header->sender_mac, 6);

          clib_memcpy(arp_header->sender_mac,
                      arp_header->target_mac, 6);

          clib_memcpy(arp_header->target_mac,
                      temp_mac, 6);

          /* ARP IP swap */
          u32 temp_ip;
          clib_memcpy(&temp_ip,
                      arp_header->sender_ip, 4);

          clib_memcpy(arp_header->sender_ip,
                      arp_header->target_ip, 4);

          clib_memcpy(arp_header->target_ip,
                      &temp_ip, 4);

          arp_header->opcode =
            clib_host_to_net_u16(2);

          vnet_buffer(current_packet_buffer)->sw_if_index[VLIB_TX] =
            vnet_buffer(current_packet_buffer)->sw_if_index[VLIB_RX];

          next_node_index = 0; // send out
        }
      }
    }

    vlib_set_next_frame_buffer(vm,
                               node_runtime,
                               next_node_index,
                               current_packet_index);
  }

  return frame->n_vectors;
}

/* ===================== NODE REGISTRATION ===================== */
VLIB_REGISTER_NODE (my_arp_node) = {
  .name = "my-arp-node",
  .vector_size = sizeof(u32),
  .format_trace = format_my_arp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_TRACE,

  .n_next_nodes = 2,
  .next_nodes = {
    [0] = "interface-output",
    [1] = "error-drop",
  },
};

/* ===================== FEATURE ATTACH ===================== */
VNET_FEATURE_INIT (my_arp_feature, static) = {
  .arc_name = "device-input",
  .node_name = "my-arp-node",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

/* ===================== INIT FUNCTION ===================== */
static clib_error_t *
myarp_init (vlib_main_t * vm)
{
  myarp_main.vlib_main = vm;
  myarp_main.vnet_main = vnet_get_main();
  return 0;
}

VLIB_INIT_FUNCTION (myarp_init);

/* ===================== PLUGIN REGISTRATION ===================== */
VLIB_PLUGIN_REGISTER () = {
  .version = "1.0",
  .description = "Custom ARP Responder Plugin (No VPP ARP stack)",
};