add_vpp_plugin(traceplugin
  SOURCES
  traceable_plugins.c

  LINK_LIBRARIES
  vppinfra
  vlib
  vnet
)